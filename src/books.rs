//! What the authority's ACME server keeps and how a request is answered:
//! its nonces, its accounts and the orders and authorizations each has
//! placed, in memory for as long as it serves (RFC 8555 section 7).
//!
//! Every signed request is held to the same rules before it is routed: a
//! nonce this server gave and has not taken back, the URL it was sent to,
//! and a signature by the account's key — the key itself only on
//! `newAccount`, the account's URL after.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use acme::Jwk;
use acme::jws::{Signed, Signer};
use net::http::{Request, Response};
use serde_json::{Value, json};

use crate::Authority;
use crate::problem::Problem;
use crate::validation::DnsLookup;

/// How the authority issues and validates.
pub struct Policy {
    /// How long a node's certificate is valid, in seconds.
    pub lifetime: i64,
    /// The port http-01 is asked on.
    pub challenge_port: u16,
    /// The DNS lookup dns-01 is validated by; without one, http-01 alone is
    /// offered.
    pub dns: Option<Arc<dyn DnsLookup>>,
}

/// One order an account placed.
pub(crate) struct OrderBook {
    pub(crate) account: usize,
    pub(crate) names: Vec<String>,
    pub(crate) authorizations: Vec<usize>,
    pub(crate) status: &'static str,
    pub(crate) chain: Option<String>,
}

/// One name to prove.
pub(crate) struct AuthorizationBook {
    pub(crate) account: usize,
    pub(crate) name: String,
    pub(crate) token: String,
    pub(crate) status: &'static str,
    pub(crate) error: Option<String>,
}

#[derive(Default)]
pub(crate) struct State {
    nonces: HashSet<String>,
    pub(crate) accounts: Vec<Jwk>,
    pub(crate) orders: Vec<OrderBook>,
    pub(crate) authorizations: Vec<AuthorizationBook>,
}

/// The server's books, and the authority it issues from.
pub struct Books {
    pub(crate) base: String,
    pub(crate) authority: Arc<Authority>,
    pub(crate) policy: Policy,
    state: Mutex<State>,
}

/// A request signed and verified: the account that sent it and what it said.
pub(crate) struct Asked {
    pub(crate) account: usize,
    pub(crate) payload: Value,
}

impl Books {
    /// Books for a server reached at `base`, `https://host:port`.
    #[must_use]
    pub fn new(base: String, authority: Arc<Authority>, policy: Policy) -> Self {
        Self {
            base,
            authority,
            policy,
            state: Mutex::new(State::default()),
        }
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// The directory's URL.
    #[must_use]
    pub fn directory(&self) -> String {
        self.url("/directory")
    }

    /// The answer to `request`, a fresh nonce on every one.
    #[must_use]
    pub fn answer(&self, request: &Request) -> Response {
        let answer = match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/directory") => Ok(json_response(
                200,
                &json!({
                    "newNonce": self.url("/new-nonce"),
                    "newAccount": self.url("/new-account"),
                    "newOrder": self.url("/new-order"),
                }),
            )),
            ("GET", "/new-nonce") => Ok(Response::new(204)),
            ("HEAD", "/new-nonce") => Ok(Response::new(200)),
            ("POST", path) => self.signed(path, &request.body),
            (_, path) => Err(Problem::new(404, "malformed", format!("nothing at {path}"))),
        };
        let nonce = codec::base64::encode_url_unpadded(&codec::random::array::<16>());
        self.state().nonces.insert(nonce.clone());
        answer
            .unwrap_or_else(|problem| problem.response())
            .header("Replay-Nonce", &nonce)
            .header("Cache-Control", "no-store")
    }

    /// A signed request, held to the rules, then routed.
    fn signed(&self, path: &str, body: &[u8]) -> Result<Response, Problem> {
        let signed = Signed::read(body)?;
        if !self.state().nonces.remove(&signed.nonce) {
            return Err(Problem::new(
                400,
                "badNonce",
                "a nonce this server did not give",
            ));
        }
        if signed.url != self.url(path) {
            return Err(Problem::unauthorized(format!(
                "signed for {} and sent to {}",
                signed.url,
                self.url(path)
            )));
        }
        if path == "/new-account" {
            return self.new_account(&signed);
        }
        let Signer::Account(account_url) = &signed.signer else {
            return Err(Problem::malformed("only newAccount is signed by a key"));
        };
        let account = account_url
            .strip_prefix(&self.url("/account/"))
            .and_then(|index| index.parse::<usize>().ok())
            .filter(|index| {
                self.state()
                    .accounts
                    .get(*index)
                    .is_some_and(|key| signed.verified_by(key))
            })
            .ok_or_else(|| Problem::new(400, "accountDoesNotExist", "no such account"))?;
        let from = Asked {
            account,
            payload: signed.json()?,
        };
        self.route(path, &from)
    }

    /// `newAccount`: the key's account, opened or found again.
    fn new_account(&self, signed: &Signed) -> Result<Response, Problem> {
        let Signer::Key(key) = &signed.signer else {
            return Err(Problem::malformed(
                "newAccount is signed by the account's key",
            ));
        };
        if !signed.verified_by(key) {
            return Err(Problem::unauthorized("the signature is not the key's"));
        }
        let mut state = self.state();
        let known = state.accounts.iter().position(|known| known == key);
        let (index, status) = known.map_or_else(
            || {
                state.accounts.push(key.clone());
                (state.accounts.len() - 1, 201)
            },
            |index| (index, 200),
        );
        Ok(json_response(status, &json!({ "status": "valid" }))
            .header("Location", &self.url(&format!("/account/{index}"))))
    }

    /// A request from an account, to the object `path` names.
    fn route(&self, path: &str, from: &Asked) -> Result<Response, Problem> {
        let mut segments = path.trim_start_matches('/').split('/');
        let (kind, index, rest) = (segments.next(), segments.next(), segments.next());
        let index = index.and_then(|index| index.parse::<usize>().ok());
        match (kind, index, rest) {
            (Some("new-order"), None, None) => self.new_order(from),
            (Some("order"), Some(index), None) => self.order(from, index),
            (Some("authz"), Some(index), None) => self.authorization(from, index),
            (Some("challenge"), Some(index), Some(kind)) => self.challenge(from, index, kind),
            (Some("finalize"), Some(index), None) => self.finalize(from, index),
            (Some("certificate"), Some(index), None) => self.certificate(from, index),
            _ => Err(Problem::new(404, "malformed", format!("nothing at {path}"))),
        }
    }
}

/// `value` as a JSON answer with `status`.
pub(crate) fn json_response(status: u16, value: &Value) -> Response {
    Response::new(status)
        .header("Content-Type", "application/json")
        .body(value.to_string().as_bytes())
}

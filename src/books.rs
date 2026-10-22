//! What the authority's ACME server keeps and how a request is answered:
//! its nonces, its accounts and the orders and authorizations each has
//! placed (RFC 8555 section 7).
//!
//! Every signed request is held to the same rules before it is routed: a
//! nonce this server gave and has not taken back, the URL it was sent to,
//! and a signature by the account's key — the key itself only on
//! `newAccount` and on a `revokeCert` signed by the certificate's own key,
//! the account's URL after.
//!
//! Accounts outlive the server: each is kept in the authority's folder,
//! `acme/accounts/<n>.json`, so a client on the premises — Xmip's own or a
//! third party's — keeps its account across a restart of the node that
//! serves; and each certificate an account was issued is noted beside it,
//! `acme/ordered/<serial>`, so the account may revoke it after one.
//! Orders and authorizations live as long as the server: a client orders
//! again.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
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
    pub(crate) expires: i64,
}

/// One name to prove.
pub(crate) struct AuthorizationBook {
    pub(crate) account: usize,
    pub(crate) name: String,
    pub(crate) token: String,
    pub(crate) status: &'static str,
    pub(crate) error: Option<String>,
    pub(crate) expires: i64,
}

#[derive(Default)]
pub(crate) struct State {
    nonces: HashSet<String>,
    pub(crate) accounts: Vec<Jwk>,
    pub(crate) orders: Vec<OrderBook>,
    pub(crate) authorizations: Vec<AuthorizationBook>,
    /// The certificates an order said it replaces (RFC 9773 section 5).
    pub(crate) replaced: HashSet<String>,
}

/// The server's books, and the authority it issues from.
pub struct Books {
    pub(crate) base: String,
    pub(crate) authority: Arc<Authority>,
    pub(crate) policy: Policy,
    /// Where accounts and who ordered what are kept; none for an authority
    /// held in memory.
    kept: Option<PathBuf>,
    state: Mutex<State>,
}

/// A request signed and verified: the account that sent it and what it said.
pub(crate) struct Asked {
    pub(crate) account: usize,
    pub(crate) payload: Value,
}

/// The folder accounts are kept in, beneath the ACME service's.
const ACCOUNTS: &str = "accounts";
/// The folder the account each certificate was ordered by is noted in.
const ORDERED: &str = "ordered";

impl Books {
    /// Books for a server reached at `base`, `https://host:port`, its
    /// accounts read from the authority's folder where it keeps one.
    #[must_use]
    pub fn new(base: String, authority: Arc<Authority>, policy: Policy) -> Self {
        let kept = authority
            .issuer()
            .register()
            .map(|register| register.place().join("acme"));
        let mut state = State::default();
        if let Some(folder) = &kept {
            state.accounts = read_accounts(&folder.join(ACCOUNTS));
        }
        Self {
            base,
            authority,
            policy,
            kept,
            state: Mutex::new(state),
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
            ("GET", "/directory") => Ok(json_response(200, &self.directory_json())),
            ("GET", "/new-nonce") => Ok(Response::new(204)),
            ("HEAD", "/new-nonce") => Ok(Response::new(200)),
            ("GET", path) if path.starts_with("/renewal-info/") => {
                self.renewal_info(&path["/renewal-info/".len()..])
            }
            ("GET", path) => crate::server::published(&self.authority, path)
                .ok_or_else(|| Problem::new(404, "malformed", format!("nothing at {path}"))),
            ("POST", path) => self.signed(path, &request.body),
            (_, path) => Err(Problem::new(404, "malformed", format!("nothing at {path}"))),
        };
        let nonce = codec::base64::encode_url_unpadded(&codec::random::array::<16>());
        self.state().nonces.insert(nonce.clone());
        answer
            .unwrap_or_else(|problem| problem.response())
            .header("Replay-Nonce", &nonce)
            .header("Cache-Control", "no-store")
            .header("Link", &format!("<{}>;rel=\"index\"", self.directory()))
    }

    /// The directory object (RFC 8555 section 7.1.1), `renewalInfo` its
    /// RFC 9773 member; no terms of service and no external account.
    fn directory_json(&self) -> Value {
        json!({
            "newNonce": self.url("/new-nonce"),
            "newAccount": self.url("/new-account"),
            "newOrder": self.url("/new-order"),
            "revokeCert": self.url("/revoke-cert"),
            "renewalInfo": self.url("/renewal-info"),
            "meta": { "externalAccountRequired": false },
        })
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
        let account_url = match &signed.signer {
            Signer::Key(key) if path == "/revoke-cert" => {
                return self.revoke_by_key(&signed, key);
            }
            Signer::Key(_) => {
                return Err(Problem::malformed(
                    "only newAccount and revokeCert are signed by a key",
                ));
            }
            Signer::Account(account_url) => account_url,
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

    /// `newAccount`: the key's account, opened or found again; with
    /// `onlyReturnExisting`, found or refused.
    fn new_account(&self, signed: &Signed) -> Result<Response, Problem> {
        let Signer::Key(key) = &signed.signer else {
            return Err(Problem::malformed(
                "newAccount is signed by the account's key",
            ));
        };
        if !signed.verified_by(key) {
            return Err(Problem::unauthorized("the signature is not the key's"));
        }
        let existing = signed.json()?.get("onlyReturnExisting") == Some(&Value::Bool(true));
        let mut state = self.state();
        let (index, status) = match state.accounts.iter().position(|known| known == key) {
            Some(index) => (index, 200),
            None if existing => {
                return Err(Problem::new(400, "accountDoesNotExist", "no such account"));
            }
            None => {
                state.accounts.push(key.clone());
                let index = state.accounts.len() - 1;
                self.keep_account(index, key)?;
                (index, 201)
            }
        };
        drop(state);
        Ok(json_response(status, &self.account_json(index))
            .header("Location", &self.url(&format!("/account/{index}"))))
    }

    /// An account object (RFC 8555 section 7.1.2).
    fn account_json(&self, index: usize) -> Value {
        json!({
            "status": "valid",
            "orders": self.url(&format!("/account/{index}/orders")),
        })
    }

    /// A request from an account, to the object `path` names.
    fn route(&self, path: &str, from: &Asked) -> Result<Response, Problem> {
        let mut segments = path.trim_start_matches('/').split('/');
        let (kind, index, rest) = (segments.next(), segments.next(), segments.next());
        let index = index.and_then(|index| index.parse::<usize>().ok());
        match (kind, index, rest) {
            (Some("new-order"), None, None) => self.new_order(from),
            (Some("revoke-cert"), None, None) => self.revoke_by_account(from),
            (Some("account"), Some(index), None) if index == from.account => {
                Ok(json_response(200, &self.account_json(index)))
            }
            (Some("account"), Some(index), Some("orders")) if index == from.account => Ok(
                json_response(200, &json!({ "orders": self.orders_of(index) })),
            ),
            (Some("order"), Some(index), None) => self.order(from, index),
            (Some("authz"), Some(index), None) => self.authorization(from, index),
            (Some("challenge"), Some(index), Some(kind)) => self.challenge(from, index, kind),
            (Some("finalize"), Some(index), None) => self.finalize(from, index),
            (Some("certificate"), Some(index), None) => self.certificate(from, index),
            _ => Err(Problem::new(404, "malformed", format!("nothing at {path}"))),
        }
    }

    /// The URL of every order `account` placed.
    fn orders_of(&self, account: usize) -> Vec<String> {
        let state = self.state();
        state
            .orders
            .iter()
            .enumerate()
            .filter(|(_, order)| order.account == account)
            .map(|(index, _)| self.url(&format!("/order/{index}")))
            .collect()
    }

    /// Keep the account `index`, its key, so it outlives the server.
    fn keep_account(&self, index: usize, key: &Jwk) -> Result<(), Problem> {
        let Some(folder) = &self.kept else {
            return Ok(());
        };
        let folder = folder.join(ACCOUNTS);
        let path = folder.join(format!("{index}.json"));
        secret::private_file::directory(&folder)
            .and_then(|()| {
                secret::private_file::create_readable(&path, key.json().to_string().as_bytes())
            })
            .map_err(|failure| Problem::new(500, "serverInternal", failure.to_string()))
    }

    /// Note that `account` was issued the certificate `serial`.
    pub(crate) fn note_ordered(&self, serial: &str, account: usize) -> Result<(), Problem> {
        let Some(folder) = &self.kept else {
            return Ok(());
        };
        let folder = folder.join(ORDERED);
        secret::private_file::directory(&folder)
            .and_then(|()| {
                secret::private_file::create_readable(
                    &folder.join(serial),
                    account.to_string().as_bytes(),
                )
            })
            .map_err(|failure| Problem::new(500, "serverInternal", failure.to_string()))
    }

    /// The account the certificate `serial` was ordered by, where one was.
    pub(crate) fn ordered_by(&self, serial: &str) -> Option<usize> {
        let folder = self.kept.as_ref()?.join(ORDERED);
        std::fs::read_to_string(folder.join(serial))
            .ok()
            .and_then(|text| text.trim().parse().ok())
    }
}

/// Every account kept in `folder`, in the order they were opened; one that
/// does not read leaves its place empty of any key.
fn read_accounts(folder: &Path) -> Vec<Jwk> {
    let mut accounts = Vec::new();
    for index in 0.. {
        let Ok(text) = std::fs::read_to_string(folder.join(format!("{index}.json"))) else {
            break;
        };
        match serde_json::from_str(&text).map(|value: Value| Jwk::from_json(&value)) {
            Ok(Ok(key)) => accounts.push(key),
            _ => break,
        }
    }
    accounts
}

/// `value` as a JSON answer with `status`.
pub(crate) fn json_response(status: u16, value: &Value) -> Response {
    Response::new(status)
        .header("Content-Type", "application/json")
        .body(value.to_string().as_bytes())
}

/// `unix` as RFC 3339 writes it, in UTC (`codec::civil`).
pub(crate) fn rfc3339(unix: i64) -> String {
    codec::civil::rfc3339_nanos(i128::from(unix) * 1_000_000_000)
}

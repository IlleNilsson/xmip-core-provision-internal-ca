//! An account's orders: placed, each name's authorization proven by the
//! challenge the node answered, finalized with a CSR into a certificate
//! the cluster's authority issues for server and client authentication.

use net::http::Response;
use provision::{Purpose, csr};
use serde_json::{Value, json};

use crate::books::{Asked, AuthorizationBook, Books, OrderBook, State, json_response};
use crate::problem::Problem;
use crate::validation;

impl Books {
    /// `newOrder`: an authorization a name, each with its challenges.
    pub(crate) fn new_order(&self, from: &Asked) -> Result<Response, Problem> {
        let identifiers = from
            .payload
            .get("identifiers")
            .and_then(Value::as_array)
            .filter(|listed| !listed.is_empty())
            .ok_or_else(|| Problem::malformed("an order names its identifiers"))?;
        let mut names = Vec::new();
        for identifier in identifiers {
            let value = identifier
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if identifier.get("type").and_then(Value::as_str) != Some("dns")
                || value.is_empty()
                || value.starts_with("*.")
            {
                return Err(Problem::new(
                    400,
                    "rejectedIdentifier",
                    format!("the cluster's authority issues for DNS names, not {identifier}"),
                ));
            }
            names.push(value.to_ascii_lowercase());
        }
        let mut state = self.state();
        let mut authorizations = Vec::new();
        for name in &names {
            state.authorizations.push(AuthorizationBook {
                account: from.account,
                name: name.clone(),
                token: codec::base64::encode_url_unpadded(&codec::random::array::<32>()),
                status: "pending",
                error: None,
            });
            authorizations.push(state.authorizations.len() - 1);
        }
        state.orders.push(OrderBook {
            account: from.account,
            names,
            authorizations,
            status: "pending",
            chain: None,
        });
        let index = state.orders.len() - 1;
        let body = self.order_json(&state.orders[index], index);
        Ok(json_response(201, &body).header("Location", &self.url(&format!("/order/{index}"))))
    }

    /// An order, as its account asks for it again.
    pub(crate) fn order(&self, from: &Asked, index: usize) -> Result<Response, Problem> {
        let state = self.state();
        let order = state
            .orders
            .get(index)
            .filter(|order| order.account == from.account)
            .ok_or_else(|| Problem::new(404, "malformed", "no such order"))?;
        Ok(json_response(200, &self.order_json(order, index)))
    }

    /// An authorization, with the challenges it may be proven by.
    pub(crate) fn authorization(&self, from: &Asked, index: usize) -> Result<Response, Problem> {
        let state = self.state();
        let found = owned(&state.authorizations, from, index)?;
        Ok(json_response(200, &self.authorization_json(found, index)))
    }

    /// A challenge answered: validated at once, and the authorization and
    /// its order moved on by what was found.
    pub(crate) fn challenge(
        &self,
        from: &Asked,
        index: usize,
        kind: &str,
    ) -> Result<Response, Problem> {
        let (name, token, key) = {
            let state = self.state();
            let found = owned(&state.authorizations, from, index)?;
            let key = state.accounts[from.account].clone();
            (found.name.clone(), found.token.clone(), key)
        };
        let authorization = key.key_authorization(&token);
        let checked = match (kind, &self.policy.dns) {
            ("http-01", _) => {
                validation::http01(&name, self.policy.challenge_port, &token, &authorization)
            }
            ("dns-01", Some(lookup)) => validation::dns01(lookup.as_ref(), &name, &authorization),
            _ => {
                return Err(Problem::malformed(format!(
                    "this authority offers no {kind}"
                )));
            }
        };
        let mut state = self.state();
        let found = &mut state.authorizations[index];
        match checked {
            Ok(()) => found.status = "valid",
            Err(failure) => {
                found.status = "invalid";
                found.error = Some(failure.message);
            }
        }
        let status = found.status;
        let State {
            orders,
            authorizations,
            ..
        } = &mut *state;
        let waiting = orders
            .iter_mut()
            .filter(|order| order.status == "pending" && order.authorizations.contains(&index));
        for order in waiting {
            if status != "valid" {
                order.status = "invalid";
            } else if order
                .authorizations
                .iter()
                .all(|one| authorizations[*one].status == "valid")
            {
                order.status = "ready";
            }
        }
        drop(state);
        let url = self.url(&format!("/challenge/{index}/{kind}"));
        Ok(
            json_response(200, &challenge_json(kind, &url, &token, status, None)).header(
                "Link",
                &format!("<{}>;rel=\"up\"", self.url(&format!("/authz/{index}"))),
            ),
        )
    }

    /// `finalize`: the CSR's names must be the order's, and the certificate
    /// is issued for its key.
    pub(crate) fn finalize(&self, from: &Asked, index: usize) -> Result<Response, Problem> {
        let request = from
            .payload
            .get("csr")
            .and_then(Value::as_str)
            .ok_or_else(|| Problem::malformed("finalize carries a csr"))?;
        let requested = csr::read(
            &codec::base64::decode_url(request)
                .map_err(|failure| Problem::new(400, "badCSR", failure.message))?,
        )
        .map_err(|failure| Problem::new(400, "badCSR", failure.message))?;
        Purpose::Node
            .admit(&requested)
            .map_err(|failure| Problem::new(400, "badCSR", failure.message))?;
        let mut state = self.state();
        let order = state
            .orders
            .get_mut(index)
            .filter(|order| order.account == from.account)
            .ok_or_else(|| Problem::new(404, "malformed", "no such order"))?;
        if order.status != "ready" {
            return Err(Problem::new(
                403,
                "orderNotReady",
                format!("the order is {}", order.status),
            ));
        }
        let mut asked: Vec<String> = requested
            .names
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();
        let mut ordered = order.names.clone();
        asked.sort();
        ordered.sort();
        if asked != ordered {
            return Err(Problem::new(
                400,
                "badCSR",
                "the CSR names other names than the order",
            ));
        }
        let now = provision::now();
        let chain = self.authority.issue(
            &requested.public_key_info,
            &order.names,
            Purpose::Node,
            now,
            now + self.policy.lifetime,
        )?;
        order.chain = Some(chain);
        order.status = "valid";
        let body = self.order_json(&state.orders[index], index);
        Ok(json_response(200, &body))
    }

    /// The chain a valid order was issued, leaf first.
    pub(crate) fn certificate(&self, from: &Asked, index: usize) -> Result<Response, Problem> {
        let state = self.state();
        let chain = state
            .orders
            .get(index)
            .filter(|order| order.account == from.account)
            .and_then(|order| order.chain.clone())
            .ok_or_else(|| Problem::new(404, "malformed", "no such certificate"))?;
        Ok(Response::new(200)
            .header("Content-Type", "application/pem-certificate-chain")
            .body(chain.as_bytes()))
    }

    fn order_json(&self, order: &OrderBook, index: usize) -> Value {
        let identifiers: Vec<Value> = order
            .names
            .iter()
            .map(|name| json!({ "type": "dns", "value": name }))
            .collect();
        let authorizations: Vec<String> = order
            .authorizations
            .iter()
            .map(|at| self.url(&format!("/authz/{at}")))
            .collect();
        let mut body = json!({
            "status": order.status,
            "identifiers": identifiers,
            "authorizations": authorizations,
            "finalize": self.url(&format!("/finalize/{index}")),
        });
        if order.chain.is_some() {
            body["certificate"] = Value::String(self.url(&format!("/certificate/{index}")));
        }
        body
    }

    fn authorization_json(&self, found: &AuthorizationBook, index: usize) -> Value {
        let mut kinds = vec!["http-01"];
        if self.policy.dns.is_some() {
            kinds.push("dns-01");
        }
        let challenges: Vec<Value> = kinds
            .into_iter()
            .map(|kind| {
                let url = self.url(&format!("/challenge/{index}/{kind}"));
                challenge_json(
                    kind,
                    &url,
                    &found.token,
                    found.status,
                    found.error.as_deref(),
                )
            })
            .collect();
        json!({
            "identifier": { "type": "dns", "value": found.name },
            "status": found.status,
            "challenges": challenges,
        })
    }
}

/// The authorization `index`, where `from`'s account placed it.
fn owned<'a>(
    authorizations: &'a [AuthorizationBook],
    from: &Asked,
    index: usize,
) -> Result<&'a AuthorizationBook, Problem> {
    authorizations
        .get(index)
        .filter(|found| found.account == from.account)
        .ok_or_else(|| Problem::new(404, "malformed", "no such authorization"))
}

fn challenge_json(kind: &str, url: &str, token: &str, status: &str, error: Option<&str>) -> Value {
    let mut body = json!({ "type": kind, "url": url, "token": token, "status": status });
    if let Some(detail) = error {
        body["error"] = json!({
            "type": "urn:ietf:params:acme:error:incorrectResponse",
            "detail": detail,
        });
    }
    body
}

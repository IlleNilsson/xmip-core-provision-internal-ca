//! What a client on the premises asks about a certificate it holds: when to
//! renew it, by ACME Renewal Information (RFC 9773), and to revoke it
//! (RFC 8555 section 7.6). Both read and write the authority's register,
//! the one an operator inspects and revokes from on every surface
//! (ADR-0034, amendment 2026-10-22), so a revocation by ACME and one by an
//! operator are the same revocation, listed at once.

use acme::Jwk;
use acme::jws::Signed;
use net::http::Response;
use provision::Parsed;
use provision::crl::Reason;
use provision::renewal::{self, window};
use serde_json::{Value, json};

use crate::books::{Asked, Books, json_response, rfc3339};
use crate::problem::Problem;

/// How long a client waits before it asks for renewal information again:
/// six hours (RFC 9773 section 4.3, `Retry-After`).
const ASK_AGAIN: u32 = 6 * 3_600;

impl Books {
    /// `GET renewalInfo/<identifier>`: the window the certificate is
    /// renewed in — two thirds to three quarters of its life, the moment
    /// every Xmip reader renews at — and, for one revoked, a window already
    /// passed, so its client renews at once.
    pub(crate) fn renewal_info(&self, identifier: &str) -> Result<Response, Problem> {
        let (authority, serial) =
            renewal::halves(identifier).map_err(|refused| Problem::malformed(refused.message))?;
        let own = Parsed::first(self.authority.anchor())?;
        let ours = provision::key_identifier(&own.public_key_info)? == authority;
        let register = self.authority.issuer().register();
        let found = register
            .filter(|_| ours)
            .and_then(|kept| kept.find(&codec::hex::encode(&serial)).ok())
            .ok_or_else(|| Problem::new(404, "malformed", "this authority issued no such"))?;
        let (start, end) = match &found.revoked {
            Some(_) => {
                let now = provision::now();
                (now - 2 * 3_600, now - 3_600)
            }
            None => window(found.not_before, found.not_after),
        };
        let body = json!({
            "suggestedWindow": { "start": rfc3339(start), "end": rfc3339(end) },
        });
        Ok(json_response(200, &body).header("Retry-After", &ASK_AGAIN.to_string()))
    }

    /// A new order's `replaces` (RFC 9773 section 5): a certificate this
    /// authority issued, replaced once.
    pub(crate) fn replaces(&self, from: &Asked) -> Result<(), Problem> {
        let Some(identifier) = from.payload.get("replaces").and_then(Value::as_str) else {
            return Ok(());
        };
        let (_, serial) =
            renewal::halves(identifier).map_err(|refused| Problem::malformed(refused.message))?;
        let serial = codec::hex::encode(&serial).to_ascii_uppercase();
        let issued = self
            .authority
            .issuer()
            .register()
            .is_some_and(|register| register.find(&serial).is_ok());
        if !issued {
            return Err(Problem::malformed(format!(
                "the order replaces {identifier}, which this authority did not issue"
            )));
        }
        if !self.state().replaced.insert(serial) {
            return Err(Problem::new(
                409,
                "alreadyReplaced",
                format!("{identifier} was replaced by an order already"),
            ));
        }
        Ok(())
    }

    /// `revokeCert` signed by an account: one this authority issued the
    /// certificate to.
    pub(crate) fn revoke_by_account(&self, from: &Asked) -> Result<Response, Problem> {
        let (read, reason) = asked(&from.payload)?;
        if self.ordered_by(&read.serial_hex()) != Some(from.account) {
            return Err(Problem::unauthorized(
                "this account was not issued the certificate",
            ));
        }
        self.revoked(&read, reason)
    }

    /// `revokeCert` signed by the certificate's own key.
    pub(crate) fn revoke_by_key(&self, signed: &Signed, key: &Jwk) -> Result<Response, Problem> {
        if !signed.verified_by(key) {
            return Err(Problem::unauthorized("the signature is not the key's"));
        }
        let (read, reason) = asked(&signed.json()?)?;
        let point = provision::point_of(&read.public_key_info)?;
        if point != key.point() {
            return Err(Problem::unauthorized(
                "the request is signed by another key than the certificate's",
            ));
        }
        self.revoked(&read, reason)
    }

    /// The certificate revoked in the register and listed at once.
    fn revoked(&self, read: &Parsed, reason: Reason) -> Result<Response, Problem> {
        match self
            .authority
            .issuer()
            .revoke(&read.serial_hex(), reason, provision::now())
        {
            Ok(_) => Ok(Response::new(200)),
            Err(refused) if refused.message.contains("revoked already") => {
                Err(Problem::new(400, "alreadyRevoked", refused.message))
            }
            Err(refused) => Err(Problem::malformed(refused.message)),
        }
    }
}

/// The certificate a `revokeCert` names and the reason it gives, held to
/// the reasons this authority revokes for.
fn asked(payload: &Value) -> Result<(Parsed, Reason), Problem> {
    let der = payload
        .get("certificate")
        .and_then(Value::as_str)
        .ok_or_else(|| Problem::malformed("revokeCert names the certificate"))
        .and_then(|text| {
            codec::base64::decode_url(text).map_err(|failure| Problem::malformed(failure.message))
        })?;
    let reason = match payload.get("reason").and_then(Value::as_u64) {
        None => Reason::Unspecified,
        Some(code) => Reason::of_code(code)
            .map_err(|refused| Problem::new(400, "badRevocationReason", refused.message))?,
    };
    Ok((Parsed::read(&der)?, reason))
}

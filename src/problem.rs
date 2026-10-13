//! A refusal as ACME writes one: a problem document (RFC 7807) whose type
//! is one of RFC 8555 section 6.7's.

use net::http::Response;
use serde_json::json;

/// One refusal: its status, its ACME error type and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The HTTP status.
    pub status: u16,
    /// The last part of `urn:ietf:params:acme:error:<kind>`.
    pub kind: &'static str,
    /// Why, in words.
    pub detail: String,
}

impl Problem {
    /// `kind` with `status`, saying `detail`.
    #[must_use]
    pub fn new(status: u16, kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            kind,
            detail: detail.into(),
        }
    }

    /// A request that is not what ACME says.
    #[must_use]
    pub fn malformed(detail: impl Into<String>) -> Self {
        Self::new(400, "malformed", detail)
    }

    /// A request from an account that may not ask it.
    #[must_use]
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(403, "unauthorized", detail)
    }

    /// The answer it is.
    #[must_use]
    pub fn response(&self) -> Response {
        let document = json!({
            "type": format!("urn:ietf:params:acme:error:{}", self.kind),
            "detail": self.detail,
            "status": self.status,
        });
        Response::new(self.status)
            .header("Content-Type", "application/problem+json")
            .body(document.to_string().as_bytes())
    }
}

impl From<provision::ProvisionError> for Problem {
    fn from(error: provision::ProvisionError) -> Self {
        Self::malformed(error.message)
    }
}

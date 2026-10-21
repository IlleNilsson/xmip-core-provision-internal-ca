//! The cluster's authority: a root key and its self-signed certificate,
//! kept in a directory, issuing node certificates under it and signing a
//! person's request. What it signs and how, and how the root is made and
//! kept, is the capability's (`provision::Issuer`, written once, the web
//! host's authority on this machine made the same way since 2026-10-21);
//! issuing to the cluster's nodes and serving ACME is this technology's.

use std::path::Path;

use provision::{Issuer, ProvisionError, Purpose, Result};

/// The cluster's own certificate authority.
pub struct Authority {
    name: String,
    issuer: Issuer,
}

impl core::fmt::Debug for Authority {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authority")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Authority {
    /// A new authority called `name`, valid from `now` for `lifetime`
    /// seconds (`Issuer::made`).
    ///
    /// # Errors
    ///
    /// Where a key cannot be made or the certificate signed.
    pub fn create(name: &str, now: i64, lifetime: i64) -> Result<Self> {
        Ok(Self {
            name: name.to_string(),
            issuer: Issuer::made(name, now, lifetime)?,
        })
    }

    /// The authority kept in `place`, or a new one called `name` created and
    /// kept there where it keeps none, as the capability keeps one
    /// (`Issuer::kept_or_made`, where the order the files are written in
    /// and why is said).
    ///
    /// # Errors
    ///
    /// Where the files cannot be read or written, or do not hold an
    /// authority.
    pub fn kept(place: &Path, name: &str, now: i64, lifetime: i64) -> Result<Self> {
        Ok(Self {
            name: name.to_string(),
            issuer: Issuer::kept_or_made(place, name, now, lifetime)?,
        })
    }

    /// Its certificate, PEM: the anchor every node of the cluster trusts.
    #[must_use]
    pub fn anchor(&self) -> &str {
        self.issuer.certificate()
    }

    /// A certificate for `public_key_info` and `names`, for `purpose`, from
    /// `not_before` to `not_after`, as a chain: the leaf, then the anchor.
    ///
    /// # Errors
    ///
    /// Where `names` is empty or signing fails.
    pub fn issue(
        &self,
        public_key_info: &[u8],
        names: &[String],
        purpose: Purpose,
        not_before: i64,
        not_after: i64,
    ) -> Result<String> {
        let subject = names
            .first()
            .ok_or_else(|| ProvisionError::new("a certificate names at least one DNS name"))?;
        self.issuer.issue(
            public_key_info,
            subject,
            names,
            purpose,
            not_before,
            not_after,
        )
    }

    /// A certificate for the request `der` — a person's, for
    /// `Purpose::Operator` — once its signature verifies and `purpose`
    /// admits it, from `not_before` to `not_after`, as a chain.
    ///
    /// # Errors
    ///
    /// Where the request does not verify or asks for more than `purpose`
    /// allows, in words.
    pub fn sign(
        &self,
        der: &[u8],
        purpose: Purpose,
        not_before: i64,
        not_after: i64,
    ) -> Result<String> {
        self.issuer.sign(der, purpose, not_before, not_after)
    }
}

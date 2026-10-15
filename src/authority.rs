//! The cluster's authority: a root key and its self-signed certificate,
//! kept in a directory, issuing node certificates under it and signing a
//! person's request. What it signs and how is the capability's
//! (`provision::Issuer`, written once); making the root and keeping it is
//! this technology's.

use std::path::Path;

use provision::issuer::{CERTIFICATE, KEY};
use provision::{Draft, Issuer, KeyPair, ProvisionError, Purpose, Result, Usage, pem};

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
    /// seconds.
    ///
    /// # Errors
    ///
    /// Where a key cannot be made or the certificate signed.
    pub fn create(name: &str, now: i64, lifetime: i64) -> Result<Self> {
        let key = KeyPair::generate()?;
        let der = Draft {
            subject: name,
            names: &[],
            public_key_info: &key.public_key_info(),
            not_before: now,
            not_after: now + lifetime,
            usage: Usage::Authority,
        }
        .sign(name, &key)?;
        Ok(Self {
            name: name.to_string(),
            issuer: Issuer::new(pem::encode("CERTIFICATE", &der), key)?,
        })
    }

    /// The authority kept in `place`, or a new one called `name` created and
    /// kept there where it keeps none.
    ///
    /// # Errors
    ///
    /// Where the files cannot be read or written, or do not hold an
    /// authority.
    pub fn kept(place: &Path, name: &str, now: i64, lifetime: i64) -> Result<Self> {
        if place.join(KEY).exists() {
            return Ok(Self {
                name: name.to_string(),
                issuer: Issuer::kept(place)?,
            });
        }
        let failed = |path: &Path, failure: std::io::Error| {
            ProvisionError::new(format!("{}: {failure}", path.display()))
        };
        let created = Self::create(name, now, lifetime)?;
        std::fs::create_dir_all(place).map_err(|failure| failed(place, failure))?;
        let certificate_path = place.join(CERTIFICATE);
        std::fs::write(&certificate_path, created.anchor())
            .map_err(|failure| failed(&certificate_path, failure))?;
        let key_path = place.join(KEY);
        std::fs::write(&key_path, created.issuer.key().pem().as_bytes())
            .map_err(|failure| failed(&key_path, failure))?;
        Ok(created)
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

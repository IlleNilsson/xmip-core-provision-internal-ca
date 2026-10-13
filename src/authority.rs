//! The cluster's authority: a root key and its self-signed certificate,
//! kept in a directory, issuing node certificates under it.

use std::path::Path;

use provision::{Draft, KeyPair, ProvisionError, Purpose, Result, Usage, pem};

/// The files the authority is kept in.
const KEY: &str = "authority.key";
const CERTIFICATE: &str = "authority.pem";

/// The cluster's own certificate authority.
pub struct Authority {
    name: String,
    key: KeyPair,
    certificate: String,
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
            key,
            certificate: pem::encode("CERTIFICATE", &der),
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
        let failed = |path: &Path, failure: std::io::Error| {
            ProvisionError::new(format!("{}: {failure}", path.display()))
        };
        let key_path = place.join(KEY);
        let certificate_path = place.join(CERTIFICATE);
        match std::fs::read_to_string(&key_path) {
            Ok(key) => {
                let certificate = std::fs::read_to_string(&certificate_path)
                    .map_err(|failure| failed(&certificate_path, failure))?;
                Ok(Self {
                    name: name.to_string(),
                    key: KeyPair::from_pem(&key)?,
                    certificate,
                })
            }
            Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {
                let created = Self::create(name, now, lifetime)?;
                std::fs::create_dir_all(place).map_err(|failure| failed(place, failure))?;
                std::fs::write(&certificate_path, &created.certificate)
                    .map_err(|failure| failed(&certificate_path, failure))?;
                std::fs::write(&key_path, created.key.pem().as_bytes())
                    .map_err(|failure| failed(&key_path, failure))?;
                Ok(created)
            }
            Err(failure) => Err(failed(&key_path, failure)),
        }
    }

    /// Its certificate, PEM: the anchor every node of the cluster trusts.
    #[must_use]
    pub fn anchor(&self) -> &str {
        &self.certificate
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
        let der = Draft {
            subject,
            names,
            public_key_info,
            not_before,
            not_after,
            usage: Usage::Leaf(purpose),
        }
        .sign(&self.name, &self.key)?;
        Ok(format!(
            "{}{}",
            pem::encode("CERTIFICATE", &der),
            self.certificate
        ))
    }
}

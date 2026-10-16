//! The cluster's authority: a root key and its self-signed certificate,
//! kept in a directory, issuing node certificates under it and signing a
//! person's request. What it signs and how is the capability's
//! (`provision::Issuer`, written once); making the root and keeping it is
//! this technology's.

use std::path::Path;

use provision::issuer::{CERTIFICATE, KEY};
use provision::{Draft, Issuer, KeyPair, ProvisionError, Purpose, Result, Usage, pem};
use secret::private_file;

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
    /// Both files are private files (`secret::private_file`) in a private
    /// directory. The certificate is written first, in place of any a crash
    /// left, and the key last and never over one: the key is what says an
    /// authority is kept, so a crash between the two leaves none kept and the
    /// next start makes a new pair, never a certificate beside another's key.
    /// What a crash left between writing a file and naming it is swept first
    /// (`private_file::sweep`).
    ///
    /// # Errors
    ///
    /// Where the files cannot be read or written, or do not hold an
    /// authority.
    pub fn kept(place: &Path, name: &str, now: i64, lifetime: i64) -> Result<Self> {
        private_file::sweep(place).map_err(|failure| {
            ProvisionError::new(format!("sweeping {}: {failure}", place.display()))
        })?;
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
        private_file::directory(place).map_err(|failure| failed(place, failure))?;
        let certificate_path = place.join(CERTIFICATE);
        private_file::replace(&certificate_path, created.anchor().as_bytes())
            .map_err(|failure| failed(&certificate_path, failure))?;
        let key_path = place.join(KEY);
        private_file::create(&key_path, created.issuer.key().pem().as_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn place(test: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "xmip-internal-ca-authority-{test}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        path.join("authority")
    }

    /// Whether the certificate kept in `place` is for the key kept beside it.
    fn matching(place: &Path) -> bool {
        let key = std::fs::read_to_string(place.join(KEY)).expect("key");
        let public = KeyPair::from_pem(&key).expect("a key").public_key_info();
        let text = std::fs::read_to_string(place.join(CERTIFICATE)).expect("certificate");
        let der = pem::decode("CERTIFICATE", &text).expect("pem").remove(0);
        der.windows(public.len())
            .any(|window| window == public.as_slice())
    }

    #[test]
    fn an_authority_is_kept_privately_and_read_back_as_it_was() {
        let place = place("kept");
        let made = Authority::kept(&place, "cluster", 1_800_000_000, 3600).expect("made");
        let again = Authority::kept(&place, "cluster", 1_800_000_000, 3600).expect("read");
        assert_eq!(made.anchor(), again.anchor());
        assert!(matching(&place));
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let bits = |path: &Path| std::fs::metadata(path).expect("metadata").mode() & 0o777;
            assert_eq!(bits(&place.join(KEY)), 0o600);
            assert_eq!(bits(&place), 0o700);
        }
        #[cfg(windows)]
        {
            let described = |path: &Path| private_file::described(path).expect("described");
            let owner = |directory| private_file::owner_only(directory).expect("owner only");
            assert_eq!(described(&place.join(KEY)), owner(false));
            assert_eq!(described(&place), owner(true));
        }
        let _ = std::fs::remove_dir_all(place.parent().expect("base"));
    }

    #[test]
    fn a_crash_between_the_certificate_and_the_key_leaves_a_matching_pair_next_time() {
        let place = place("crash");
        let other = Authority::create("before the crash", 1_800_000_000, 3600).expect("made");
        private_file::replace(&place.join(CERTIFICATE), other.anchor().as_bytes())
            .expect("the certificate a crash left");
        let made = Authority::kept(&place, "cluster", 1_800_000_000, 3600).expect("made");
        assert_ne!(made.anchor(), other.anchor());
        assert!(matching(&place), "the certificate is for the key beside it");
        let _ = std::fs::remove_dir_all(place.parent().expect("base"));
    }
}

//! The cluster's authority as a node's source: its settings, declared once;
//! the node that holds the authority issuing its own certificate, and
//! serving ACME to the cluster's other nodes where it is configured to.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use provision::{KeyPair, NAMES, Order, Provisioned, Result, Source};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};
use zeroize::Zeroizing;

use crate::books::Policy;
use crate::server::Serving;
use crate::{Authority, DnsLookup};

/// The technology's module name.
pub const TECHNOLOGY: &str = "xmip-core-provision-internal-ca";

/// Where the authority is kept, inside the purpose's place.
const PLACE: &str = "authority";

/// Every setting `[provision.<purpose>]` takes with `source =
/// "xmip-core-provision-internal-ca"`.
pub const SETTINGS: &Settings = &Settings {
    technology: TECHNOLOGY,
    settings: &[
        NAMES,
        Setting {
            name: "lifetime",
            kind: Kind::Duration,
            presence: Presence::Required,
            meaning: "How long a certificate the authority issues is valid.",
            applies: Applies::Both,
        },
        Setting {
            name: "authority_lifetime",
            kind: Kind::Duration,
            presence: Presence::Required,
            meaning: "How long the authority's own certificate is valid, from when it is made.",
            applies: Applies::Both,
        },
        Setting {
            name: "serve",
            kind: Kind::Address,
            presence: Presence::Optional,
            meaning: "Where the authority answers ACME for the cluster's other nodes, host \
                      and port; absent, it issues to this node alone.",
            applies: Applies::Both,
        },
        Setting {
            name: "challenge_port",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 65_535,
            },
            presence: Presence::Default(Fixed::Integer(80)),
            meaning: "The port the authority asks a node's http-01 answer on.",
            applies: Applies::Both,
        },
    ],
};

/// The cluster's authority, configured.
#[derive(Clone, Debug)]
pub struct InternalCa {
    lifetime: i64,
    authority_lifetime: i64,
    serve: Option<String>,
    challenge_port: u16,
}

impl InternalCa {
    /// The authority as `settings`, read through [`SETTINGS`], says.
    #[must_use]
    pub fn configured(settings: &Read) -> Self {
        let seconds =
            |name: &str| i64::try_from(settings.duration(name).as_secs()).unwrap_or(i64::MAX / 2);
        Self {
            lifetime: seconds("lifetime"),
            authority_lifetime: seconds("authority_lifetime"),
            serve: settings.optional_text("serve").map(str::to_string),
            challenge_port: u16::try_from(settings.integer("challenge_port")).unwrap_or(80),
        }
    }

    /// Where it answers ACME, if it does.
    #[must_use]
    pub fn serves_on(&self) -> Option<&str> {
        self.serve.as_deref()
    }

    /// The authority kept in a purpose's place `keep`, made there the first
    /// time, its name the first of `names`'.
    ///
    /// # Errors
    ///
    /// Where it cannot be read or made.
    pub fn authority(&self, keep: &Path, names: &[String]) -> Result<Authority> {
        let first = names.first().map_or("Xmip", String::as_str);
        Authority::kept(
            &keep.join(PLACE),
            &format!("{first} cluster authority"),
            provision::now(),
            self.authority_lifetime,
        )
    }

    /// Answer ACME on `listen` for the authority kept in `keep`, reached by
    /// `names`, validating dns-01 through `dns` where there is one.
    ///
    /// # Errors
    ///
    /// Where the authority cannot be read, or the server cannot start.
    pub fn serve(
        &self,
        keep: &Path,
        listen: &str,
        names: &[String],
        dns: Option<Arc<dyn DnsLookup>>,
    ) -> Result<Serving> {
        let policy = Policy {
            lifetime: self.lifetime,
            challenge_port: self.challenge_port,
            dns,
        };
        Serving::start(
            Arc::new(self.authority(keep, names)?),
            listen,
            names,
            policy,
        )
    }

    /// How long a certificate it issues is valid.
    #[must_use]
    pub fn lifetime(&self) -> Duration {
        Duration::from_secs(u64::try_from(self.lifetime).unwrap_or(0))
    }
}

impl Source for InternalCa {
    fn technology(&self) -> &'static str {
        TECHNOLOGY
    }

    /// The node holding the authority issues its own certificate directly;
    /// every other node asks it over ACME.
    fn obtain(&self, order: &Order<'_>) -> Result<Provisioned> {
        let authority = self.authority(order.keep, order.names)?;
        let key = KeyPair::generate()?;
        let now = provision::now();
        let chain = authority.issue(
            &key.public_key_info(),
            order.names,
            order.purpose,
            now,
            now + self.lifetime,
        )?;
        Provisioned::new(
            chain,
            Zeroizing::new(key.pem().to_string()),
            Some(authority.anchor().to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declaration_is_sound() {
        assert!(SETTINGS.problems().is_empty(), "{:?}", SETTINGS.problems());
    }
}

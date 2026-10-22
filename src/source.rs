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
use crate::server::{Publishing, Serving};
use crate::{Authority, DnsLookup, Resolver};

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
        Setting {
            name: "authority",
            kind: Kind::Address,
            presence: Presence::Default(Fixed::Text("authority")),
            meaning: "The folder the authority is kept in — authority.key, authority.pem and \
                      its register — relative to the purpose's place.",
            applies: Applies::Both,
        },
        Setting {
            name: "publish",
            kind: Kind::Address,
            presence: Presence::Optional,
            meaning: "Where the authority publishes its revocation list and its certificate \
                      over plain HTTP, host and port; absent, they are fetched from its ACME \
                      service alone.",
            applies: Applies::Both,
        },
        Setting {
            name: "published_at",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "The address the premises reach that publication at, http://host:port, \
                      which every certificate it signs names.",
            applies: Applies::Both,
        },
        Setting {
            name: "dns_server",
            kind: Kind::Address,
            presence: Presence::Optional,
            meaning: "The DNS server on the premises dns-01 is checked against, host and \
                      port; absent, http-01 alone is offered.",
            applies: Applies::Both,
        },
    ],
};

/// The cluster's authority, configured.
pub struct InternalCa {
    lifetime: i64,
    authority_lifetime: i64,
    authority: String,
    serve: Option<String>,
    publish: Option<String>,
    published_at: Option<String>,
    dns_server: Option<String>,
    challenge_port: u16,
}

impl InternalCa {
    /// The authority as `settings`, read through [`SETTINGS`], says.
    #[must_use]
    pub fn configured(settings: &Read) -> Self {
        let seconds =
            |name: &str| i64::try_from(settings.duration(name).as_secs()).unwrap_or(i64::MAX / 2);
        let text = |name: &str| settings.optional_text(name).map(str::to_string);
        Self {
            lifetime: seconds("lifetime"),
            authority_lifetime: seconds("authority_lifetime"),
            authority: text("authority").unwrap_or_else(|| PLACE.to_string()),
            serve: text("serve"),
            publish: text("publish"),
            published_at: text("published_at"),
            dns_server: text("dns_server"),
            challenge_port: u16::try_from(settings.integer("challenge_port")).unwrap_or(80),
        }
    }

    /// Where it answers ACME, if it does.
    #[must_use]
    pub fn serves_on(&self) -> Option<&str> {
        self.serve.as_deref()
    }

    /// Where it publishes its list and certificate over plain HTTP, if it
    /// does.
    #[must_use]
    pub fn publishes_on(&self) -> Option<&str> {
        self.publish.as_deref()
    }

    /// The folder the authority is kept in, for the purpose's place `keep`.
    #[must_use]
    pub fn place(&self, keep: &Path) -> std::path::PathBuf {
        keep.join(&self.authority)
    }

    /// The authority kept in a purpose's place `keep`, made there the first
    /// time, its name the first of `names`', and the address it publishes
    /// at recorded where `published_at` says one.
    ///
    /// # Errors
    ///
    /// Where it cannot be read or made, or the address is not plain HTTP.
    pub fn authority(&self, keep: &Path, names: &[String]) -> Result<Authority> {
        let first = names.first().map_or("Xmip", String::as_str);
        let place = self.place(keep);
        let name = format!("{first} cluster authority");
        let made = Authority::kept(&place, &name, provision::now(), self.authority_lifetime)?;
        match (&self.published_at, made.issuer().register()) {
            (Some(address), Some(register))
                if register.published()?.as_deref() != Some(address.trim_end_matches('/')) =>
            {
                register.publish(address)?;
                Authority::kept(&place, &name, provision::now(), self.authority_lifetime)
            }
            _ => Ok(made),
        }
    }

    /// Answer ACME on `listen` for the authority kept in `keep`, reached by
    /// `names`, validating dns-01 through `dns` where there is one, else
    /// against `dns_server` where it names one.
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
        let dns = dns.or_else(|| {
            self.dns_server
                .as_deref()
                .map(|server| Arc::new(Resolver::new(server)) as Arc<dyn DnsLookup>)
        });
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

    /// Publish the authority kept in `keep` on `listen`, plain HTTP.
    ///
    /// # Errors
    ///
    /// Where the authority cannot be read, or `listen` cannot be bound.
    pub fn publish(&self, keep: &Path, listen: &str, names: &[String]) -> Result<Publishing> {
        Publishing::start(Arc::new(self.authority(keep, names)?), listen)
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

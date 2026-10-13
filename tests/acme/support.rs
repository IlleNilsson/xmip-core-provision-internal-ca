//! What the tests share: a place on disk, a free port, settings read as a
//! node's configuration would give them, and a DNS zone in memory that a
//! provider's writer and the authority's lookup both reach.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use acme::DnsWriter;
use provision::{Configured, ProvisionError};
use xcore::settings::{Given, Settings};
use xmip_core_provision_internal_ca::DnsLookup;

/// A fresh directory under the system's temporary one, removed on drop.
pub struct Place(pub PathBuf);

impl Place {
    pub fn new() -> Self {
        let name = codec::hex::encode(&codec::random::array::<8>());
        let path = std::env::temp_dir().join(format!("xmip-provision-{name}"));
        std::fs::create_dir_all(&path).expect("a place");
        Self(path)
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The address `localhost` resolves to first, which a connection to it
/// tries first: listening there, nothing waits on the refusal of another.
pub fn loopback(port: u16) -> String {
    use std::net::ToSocketAddrs;
    let mut first = ("localhost", port)
        .to_socket_addrs()
        .expect("localhost resolves")
        .next()
        .expect("to an address");
    first.set_port(port);
    first.to_string()
}

/// A port on [`loopback`] nothing listens on now.
pub fn free_port() -> u16 {
    let held = std::net::TcpListener::bind(loopback(0)).expect("a port");
    held.local_addr().expect("address").port()
}

/// `[provision.<purpose>]` as the given keys and values, read against
/// `sources`.
pub fn configured(
    purpose: &str,
    given: &[(&str, &str)],
    sources: &[&'static Settings],
) -> Result<Configured, xcore::settings::Refused> {
    let given: Vec<(String, Given)> = given
        .iter()
        .map(|(key, value)| ((*key).to_string(), Given::Text((*value).to_string())))
        .collect();
    provision::read(purpose, &given, sources)
}

/// A zone held in memory: TXT records by name.
#[derive(Default)]
pub struct Zone(Mutex<HashMap<String, Vec<String>>>);

impl Zone {
    pub fn count(&self) -> usize {
        self.0.lock().expect("zone").values().map(Vec::len).sum()
    }
}

impl DnsWriter for Zone {
    fn publish(&self, name: &str, value: &str) -> provision::Result<()> {
        let mut zone = self.0.lock().map_err(|_| ProvisionError::new("zone"))?;
        zone.entry(name.to_string())
            .or_default()
            .push(value.to_string());
        Ok(())
    }

    fn withdraw(&self, name: &str, value: &str) -> provision::Result<()> {
        let mut zone = self.0.lock().map_err(|_| ProvisionError::new("zone"))?;
        if let Some(values) = zone.get_mut(name) {
            values.retain(|held| held != value);
        }
        Ok(())
    }
}

impl DnsLookup for Zone {
    fn txt(&self, name: &str) -> provision::Result<Vec<String>> {
        let zone = self.0.lock().map_err(|_| ProvisionError::new("zone"))?;
        Ok(zone.get(name).cloned().unwrap_or_default())
    }
}

/// The zone as both halves.
pub fn zone() -> (Arc<Zone>, Arc<dyn DnsWriter>, Arc<dyn DnsLookup>) {
    let zone = Arc::new(Zone::default());
    let writer: Arc<dyn DnsWriter> = zone.clone();
    let lookup: Arc<dyn DnsLookup> = zone.clone();
    (zone, writer, lookup)
}

//! The authority as the premises' own ACME service (ADR-0034, amendment
//! 2026-10-22): its directory offers renewal information and revocation,
//! an account outlives the server, a revocation by ACME is in the register
//! and the list at once, the list and the authority's certificate are
//! fetched over plain HTTP from the address every leaf names, and a
//! revoked certificate's renewal window has already opened.

use std::io::{BufReader, Write};
use std::path::Path;
use std::time::Duration;

use acme::{Challenge, Channel, Client};
use provision::crl::{self, Reason};
use provision::{KeyPair, Parsed};
use xcore::settings::Given;
use xmip_core_provision_internal_ca::{self as internal_ca, InternalCa, Publishing, Serving};

use crate::support::{Place, free_port, loopback};

const HOST: &str = "localhost";

/// The authority kept in `place`, serving ACME and publishing on loopback.
fn premises(place: &Path, port: u16, publish: u16) -> (InternalCa, Serving, Publishing) {
    let text = |key: &str, value: &str| (key.to_string(), Given::Text(value.to_string()));
    let published = format!("http://{}", loopback(publish));
    let read = provision::read(
        "node",
        &[
            text("source", internal_ca::TECHNOLOGY),
            text("names", HOST),
            text("lifetime", "2160h"),
            text("authority_lifetime", "87600h"),
            text("publish", &loopback(publish)),
            text("published_at", &published),
            (
                "challenge_port".to_string(),
                Given::Integer(i64::from(port)),
            ),
        ],
        &[internal_ca::SETTINGS],
    )
    .expect("the authority's settings");
    let ca = InternalCa::configured(&read.settings);
    let names = vec![HOST.to_string()];
    let serving = ca.serve(place, &loopback(0), &names, None).expect("serves");
    let publishing = ca
        .publish(place, &loopback(publish), &names)
        .expect("publishes");
    (ca, serving, publishing)
}

/// An account at `serving`, by `key`, trusting the authority kept in
/// `place`.
fn account(ca: &InternalCa, place: &Path, serving: &Serving, key: KeyPair) -> Client {
    let anchor = ca.authority(place, &[HOST.to_string()]).expect("kept");
    let channel = Channel::new(Some(anchor.anchor()), Duration::from_secs(5)).expect("channel");
    Client::open(channel, serving.directory(), key, None, true).expect("an account")
}

/// `GET path` over plain HTTP from `address`: the body.
fn fetched(address: std::net::SocketAddr, path: &str) -> Vec<u8> {
    let tcp = net::connect(address, Some(Duration::from_secs(5))).expect("connects");
    let mut writer = tcp.try_clone().expect("clone");
    let request = net::http::Request::new("GET", path.to_string()).header("Host", HOST);
    net::http::write_request(&mut writer, &request).expect("asked");
    writer.flush().expect("flushed");
    let answer = net::http::read_response(&mut BufReader::new(tcp)).expect("answered");
    assert_eq!(answer.status, 200, "{path}");
    answer.body
}

#[test]
fn a_client_on_the_premises_renews_by_renewal_information_and_revokes_into_the_list() {
    let place = Place::new();
    let (port, publish) = (free_port(), free_port());
    let (ca, serving, publishing) = premises(&place.0, port, publish);
    let key = KeyPair::generate().expect("an account key");
    let pem = key.pem();
    let client = account(&ca, &place.0, &serving, key);
    let challenge = Challenge::Http01 {
        listen: loopback(port),
    };
    let wait = Duration::from_secs(10);
    let (chain, _) = client
        .certificate(&[HOST.to_string()], &challenge, wait)
        .expect("issued");
    let leaf = Parsed::first(&chain).expect("the leaf");

    let suggested = client
        .renewal_window(&chain)
        .expect("asked")
        .expect("offered");
    assert_eq!(
        suggested,
        provision::renewal::window(leaf.not_before, leaf.not_after)
    );
    let text =
        String::from_utf8_lossy(&provision::pem::decode("CERTIFICATE", &chain).expect("pem")[0])
            .into_owned();
    let published = format!("http://{}", loopback(publish));
    assert!(
        text.contains(&format!("{published}/crl")),
        "the leaf names the list"
    );

    let anchor = fetched(publishing.address(), "/authority.cer");
    let authority = Parsed::read(&anchor).expect("the authority's certificate");
    let listed = crl::read(&fetched(publishing.address(), "/crl")).expect("a list");
    assert!(listed.signed_by(&authority).expect("checked"));
    assert!(listed.names(&leaf.serial).is_none());

    // The server stops and starts again: the account is the one kept.
    drop(serving);
    let (ca, serving, publishing) = {
        drop(publishing);
        premises(&place.0, port, publish)
    };
    let again = account(
        &ca,
        &place.0,
        &serving,
        KeyPair::from_pem(&pem).expect("the same key"),
    );
    again
        .revoke(&chain, Reason::KeyCompromise.code())
        .expect("revoked by the account it was issued to");
    let listed = crl::read(&fetched(publishing.address(), "/crl")).expect("a list");
    let named = listed.names(&leaf.serial).expect("listed at once");
    assert_eq!(named.reason, Reason::KeyCompromise);
    let register = ca
        .authority(&place.0, &[HOST.to_string()])
        .expect("kept")
        .issuer()
        .register()
        .expect("a register")
        .find(&leaf.serial_hex())
        .expect("found");
    assert!(register.revoked.is_some(), "the register says so too");
    let (start, end) = again
        .renewal_window(&chain)
        .expect("asked")
        .expect("offered");
    assert!(end < provision::now() && start < end, "renew at once");
    let twice = again
        .revoke(&chain, Reason::Superseded.code())
        .expect_err("revoked already");
    assert!(twice.message.contains("alreadyRevoked"), "{twice}");

    let stranger = account(
        &ca,
        &place.0,
        &serving,
        KeyPair::generate().expect("another key"),
    );
    let (other, _) = again
        .certificate(&[HOST.to_string()], &challenge, wait)
        .expect("issued again");
    let refused = stranger
        .revoke(&other, Reason::Unspecified.code())
        .expect_err("not its own");
    assert!(refused.message.contains("unauthorized"), "{refused}");
}

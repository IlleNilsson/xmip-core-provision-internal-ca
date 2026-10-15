//! A node obtains its certificate by ACME from the cluster's authority, in
//! process and offline, and presents it on mutual TLS: open problem 27's
//! `identity-local`, without step-ca.

mod support;

use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use acme::{Acme, DnsWriter, Listening};
use internal_ca::{DnsLookup, InternalCa, Serving};
use provision::{Provisioned, Provisioner, Purpose, Source};
use support::{Place, configured, free_port, loopback, zone};
use xmip_core_provision_internal_ca as internal_ca;

/// The name every certificate here is for: the loopback host, which the
/// authority's http-01 check and the TLS client both reach.
const HOST: &str = "localhost";

/// The authority, kept in `place`, served on loopback.
fn authority(place: &Path, dns: Option<Arc<dyn DnsLookup>>, port: u16) -> (InternalCa, Serving) {
    let read = provision::read(
        "node",
        &[
            text("source", internal_ca::TECHNOLOGY),
            text("names", HOST),
            text("lifetime", "24h"),
            text("authority_lifetime", "720h"),
            (
                "challenge_port".to_string(),
                xcore::settings::Given::Integer(i64::from(port)),
            ),
        ],
        &[internal_ca::SETTINGS],
    )
    .expect("the authority's settings");
    let ca = InternalCa::configured(&read.settings);
    let names = vec![HOST.to_string()];
    let serving = ca
        .serve(place, &loopback(0), &names, dns)
        .expect("the authority serves ACME");
    (ca, serving)
}

fn text(key: &str, value: &str) -> (String, xcore::settings::Given) {
    (
        key.to_string(),
        xcore::settings::Given::Text(value.to_string()),
    )
}

/// A node's ACME source pointed at `serving`, its anchor written beside it.
fn client(
    place: &Path,
    serving: &Serving,
    ca: &InternalCa,
    keep: &Path,
    challenge: (&str, u16),
    dns: Option<Arc<dyn DnsWriter>>,
) -> Acme {
    let anchor = ca.authority(keep, &[HOST.to_string()]).expect("authority");
    std::fs::write(place.join("anchor.pem"), anchor.anchor()).expect("anchor written");
    let listen = loopback(challenge.1);
    let read = configured(
        "node",
        &[
            ("source", acme::TECHNOLOGY),
            ("directory", serving.directory()),
            ("names", HOST),
            ("challenge", challenge.0),
            ("challenge_listen", &listen),
            ("anchors", "anchor.pem"),
            ("validation_wait", "10s"),
        ],
        &[acme::SETTINGS, internal_ca::SETTINGS],
    )
    .expect("the node's settings");
    Acme::configured(&read.settings, place, dns).expect("acme configured")
}

#[test]
fn a_node_obtains_its_certificate_by_http_01_and_presents_it_on_mutual_tls() {
    let (authority_place, node_place) = (Place::new(), Place::new());
    let port = free_port();
    let (ca, serving) = authority(&authority_place.0, None, port);
    let source = client(
        &node_place.0,
        &serving,
        &ca,
        &authority_place.0,
        ("http-01", port),
        None,
    );

    let started = std::time::Instant::now();
    let names = vec![HOST.to_string()];
    let mut provisioner = Provisioner::new(
        Box::new(source),
        Purpose::Node,
        names.clone(),
        node_place.0.join("node"),
    );
    assert!(provisioner.refresh(provision::now()).expect("obtained"));
    let obtained = provisioner.held().expect("held").clone();
    eprintln!("obtained by ACME in {:?}", started.elapsed());
    assert!(obtained.chain.contains("BEGIN CERTIFICATE"));
    assert_eq!(obtained.not_after - obtained.not_before, 24 * 3600);
    assert!(std::fs::metadata(node_place.0.join("node").join("account.key")).is_ok());

    // The authority's own node issues itself directly; the two present
    // their certificates to each other.
    let order = provision::Order {
        purpose: Purpose::Node,
        names: &names,
        keep: &authority_place.0,
    };
    let direct = ca.obtain(&order).expect("issued directly");
    mutual(&obtained, &direct);
}

#[test]
fn a_node_obtains_its_certificate_by_dns_01_and_its_records_are_withdrawn() {
    let (authority_place, node_place) = (Place::new(), Place::new());
    let (records, writer, lookup) = zone();
    let (ca, serving) = authority(&authority_place.0, Some(lookup), free_port());
    let source = client(
        &node_place.0,
        &serving,
        &ca,
        &authority_place.0,
        ("dns-01", free_port()),
        Some(writer),
    );
    let names = vec![HOST.to_string()];
    let order = provision::Order {
        purpose: Purpose::Node,
        names: &names,
        keep: &node_place.0,
    };
    let obtained = source.obtain(&order).expect("obtained by dns-01");
    assert!(obtained.anchors.is_some());
    assert_eq!(records.count(), 0, "the challenge records are withdrawn");
}

#[test]
fn a_certificate_is_renewed_at_two_thirds_of_its_life_and_not_before() {
    let (authority_place, node_place) = (Place::new(), Place::new());
    let port = free_port();
    let (ca, serving) = authority(&authority_place.0, None, port);
    let source = client(
        &node_place.0,
        &serving,
        &ca,
        &authority_place.0,
        ("http-01", port),
        None,
    );
    let mut provisioner = Provisioner::new(
        Box::new(source),
        Purpose::Node,
        vec![HOST.to_string()],
        node_place.0.join("node"),
    );
    let now = provision::now();
    assert!(provisioner.refresh(now).expect("first"));
    let first = provisioner.held().expect("held").clone();
    assert_eq!(first.renew_at(), first.not_before + 16 * 3600);
    assert!(
        !provisioner
            .refresh(first.renew_at() - 1)
            .expect("not yet due")
    );
    assert!(provisioner.refresh(first.renew_at()).expect("renewed"));
    assert_ne!(provisioner.held().expect("held").chain, first.chain);

    // A provisioner started again reads what the place keeps.
    let again = Provisioned::read(&node_place.0.join("node"))
        .expect("read")
        .expect("kept");
    assert_eq!(again.chain, provisioner.held().expect("held").chain);
}

#[test]
fn a_challenge_nobody_answers_is_refused_with_the_authoritys_reason() {
    let (authority_place, node_place) = (Place::new(), Place::new());
    let (ca, serving) = authority(&authority_place.0, None, free_port());
    // The node answers on one port and the authority asks on another.
    let source = client(
        &node_place.0,
        &serving,
        &ca,
        &authority_place.0,
        ("http-01", free_port()),
        None,
    );
    let names = vec![HOST.to_string()];
    let order = provision::Order {
        purpose: Purpose::Node,
        names: &names,
        keep: &node_place.0,
    };
    let refused = source.obtain(&order).expect_err("nothing answers");
    assert!(refused.message.contains("invalid"), "{refused}");
    assert!(refused.message.contains("http-01"), "{refused}");
}

#[test]
fn an_acme_source_without_its_directory_is_refused_naming_it() {
    let refused = configured(
        "receive",
        &[("source", acme::TECHNOLOGY), ("names", HOST)],
        &[acme::SETTINGS],
    )
    .expect_err("no directory");
    assert!(refused.to_string().contains("\"directory\""), "{refused}");
    let dns = configured(
        "receive",
        &[
            ("source", acme::TECHNOLOGY),
            ("names", HOST),
            ("directory", "https://acme.example/directory"),
            ("challenge", "dns-01"),
        ],
        &[acme::SETTINGS],
    )
    .expect("read");
    let refused = Acme::configured(&dns.settings, Path::new("."), None)
        .err()
        .expect("no writer");
    assert!(refused.message.contains("DNS writer"), "{refused}");
}

#[test]
fn a_persons_request_signed_by_the_authority_is_presented_on_mutual_tls_to_its_node() {
    let place = Place::new();
    let names = vec![HOST.to_string()];
    let read = provision::read(
        "node",
        &[
            text("source", internal_ca::TECHNOLOGY),
            text("names", HOST),
            text("lifetime", "24h"),
            text("authority_lifetime", "720h"),
        ],
        &[internal_ca::SETTINGS],
    )
    .expect("the authority's settings");
    let ca = InternalCa::configured(&read.settings);
    let order = provision::Order {
        purpose: Purpose::Node,
        names: &names,
        keep: &place.0,
    };
    let node = ca.obtain(&order).expect("the node's own");

    let asked = provision::operator::request("alice@example.org").expect("a request");
    let der = provision::pem::decode(provision::operator::REQUEST_LABEL, &asked.request)
        .expect("pem")
        .remove(0);
    let authority = ca.authority(&place.0, &names).expect("kept");
    let now = provision::now();
    let chain = authority
        .sign(&der, Purpose::Operator, now, now + 3600)
        .expect("signed");
    let person = Provisioned::new(
        chain,
        asked.key.clone(),
        Some(authority.anchor().to_string()),
    )
    .expect("held");
    mutual(&node, &person);

    let refused = authority
        .sign(&der, Purpose::Node, now, now + 3600)
        .expect_err("a person is no node");
    assert!(refused.message.contains("no DNS name"), "{refused}");
}

/// Both certificates presented and verified in one mutual TLS handshake.
fn mutual(server: &Provisioned, client: &Provisioned) {
    let identity = |held: &Provisioned| {
        tls::Identity::from_pem(
            held.chain.as_bytes(),
            held.key.as_bytes(),
            held.anchors.as_deref().unwrap_or_default().as_bytes(),
        )
        .expect("an identity")
    };
    let wait = Duration::from_secs(5);
    let config = Arc::new(identity(server).server().expect("server config"));
    let (heard, hearing) = std::sync::mpsc::channel();
    let serving = Listening::start(&loopback(0), "mutual", move |tcp| {
        let _ = tcp.set_read_timeout(Some(wait));
        let Ok(mut stream) = tls::server(tcp, Arc::clone(&config)) else {
            return;
        };
        let mut asked = [0; 4];
        if stream.read_exact(&mut asked).is_ok() {
            let _ = stream.write_all(b"pong");
            let _ = stream.flush();
            let _ = heard.send(asked);
        }
    })
    .expect("listens");
    let config = Arc::new(identity(client).client().expect("client config"));
    let tcp = net::connect(serving.address(), Some(wait)).expect("connects");
    let mut stream = tls::client_with(HOST, tcp, config).expect("client tls");
    stream.write_all(b"ping").expect("written");
    let mut answer = [0; 4];
    stream.read_exact(&mut answer).expect("read");
    assert_eq!(&answer, b"pong");
    assert_eq!(&hearing.recv_timeout(wait).expect("heard"), b"ping");
}

//! A standard third-party ACME client on the premises against the
//! cluster's authority (ADR-0034, amendment 2026-10-22): lego, the Go
//! client, one binary with nothing installed, run from where
//! `XMIP_ACME_LEGO` names it. It obtains a certificate by http-01, is told
//! by renewal information (RFC 9773) that it is not yet due, revokes it,
//! and is told to renew it at once, which it does, saying the certificate
//! its order replaces. Without `XMIP_ACME_LEGO` the test says SKIPPED and
//! fails nothing, as a binding whose tool is absent does.
//!
//! lego trusts the authority through `LEGO_CA_CERTIFICATES`, a file of
//! anchors of its own: nothing is added to the machine's trust store.

use std::path::{Path, PathBuf};
use std::process::Command;

use provision::Parsed;
use provision::crl::Reason;
use xcore::settings::Given;
use xmip_core_provision_internal_ca::{self as internal_ca, InternalCa};

use crate::support::{Place, free_port, loopback};

const HOST: &str = "localhost";

/// lego, where the test is given it.
fn lego() -> Option<PathBuf> {
    std::env::var_os("XMIP_ACME_LEGO")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
}

/// lego run with `arguments` after its common ones; its output, and
/// whether it succeeded.
fn run(lego: &Path, data: &Path, anchor: &Path, directory: &str, arguments: &[&str]) -> String {
    let output = Command::new(lego)
        .args(arguments)
        .args(["--server", directory, "--path"])
        .arg(data)
        .env("LEGO_CA_CERTIFICATES", anchor)
        .env("LEGO_LOG_FORMAT", "text")
        .output()
        .expect("lego runs");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "lego {arguments:?} failed:\n{said}"
    );
    said
}

/// The certificate lego keeps for `HOST`.
fn held(data: &Path) -> Parsed {
    let path = data.join("certificates").join(format!("{HOST}.crt"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|failure| panic!("{}: {failure}", path.display()));
    Parsed::first(&text).expect("a certificate")
}

#[test]
fn lego_obtains_renews_by_renewal_information_and_revokes_against_the_authority() {
    let Some(lego) = lego() else {
        eprintln!("SKIPPED: XMIP_ACME_LEGO names no lego binary");
        return;
    };
    let (place, data) = (Place::new(), Place::new());
    let port = free_port();
    let text = |key: &str, value: &str| (key.to_string(), Given::Text(value.to_string()));
    let read = provision::read(
        "node",
        &[
            text("source", internal_ca::TECHNOLOGY),
            text("names", HOST),
            text("lifetime", "2160h"),
            text("authority_lifetime", "87600h"),
            (
                "challenge_port".to_string(),
                Given::Integer(i64::from(port)),
            ),
        ],
        &[internal_ca::SETTINGS],
    )
    .expect("settings");
    let ca = InternalCa::configured(&read.settings);
    let names = vec![HOST.to_string()];
    let serving = ca
        .serve(&place.0, &loopback(0), &names, None)
        .expect("serves");
    let authority = ca.authority(&place.0, &names).expect("kept");
    let anchor = place.0.join("anchor.pem");
    std::fs::write(&anchor, authority.anchor()).expect("the anchor");
    let address = loopback(port);
    let obtain = [
        "run",
        "--accept-tos",
        "--email",
        "operator@example.org",
        "--domains",
        HOST,
        "--http",
        "--http.address",
        &address,
        "--no-random-sleep",
    ];
    let directory = serving.directory();

    run(&lego, &data.0, &anchor, directory, &obtain);
    let first = held(&data.0);
    let register = authority.issuer().register().expect("a register");
    assert!(
        register.find(&first.serial_hex()).is_ok(),
        "issued by the authority"
    );

    let said = run(&lego, &data.0, &anchor, directory, &obtain);
    assert_eq!(held(&data.0).serial, first.serial, "not yet due:\n{said}");

    run(
        &lego,
        &data.0,
        &anchor,
        directory,
        &[
            "certificates",
            "revoke",
            "--cert.name",
            HOST,
            "--keep",
            "--reason",
            "4",
            "--email",
            "operator@example.org",
        ],
    );
    let revoked = register.find(&first.serial_hex()).expect("found");
    assert_eq!(revoked.revoked.expect("revoked").reason, Reason::Superseded);
    let listed = provision::crl::read(
        &authority
            .issuer()
            .revocation_list(provision::now())
            .expect("a list"),
    )
    .expect("read");
    assert!(listed.names(&first.serial).is_some());

    let said = run(&lego, &data.0, &anchor, directory, &obtain);
    let second = held(&data.0);
    assert_ne!(second.serial, first.serial, "renewed at once:\n{said}");
    eprintln!(
        "lego obtained {}, revoked it and renewed it as {}",
        first.serial_hex(),
        second.serial_hex()
    );
}

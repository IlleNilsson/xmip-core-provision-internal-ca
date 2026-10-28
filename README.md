# xmip-core-provision-internal-ca

The cluster's own certificate authority. A technology of
[xmip-core-provision](https://github.com/IlleNilsson/xmip-core-provision).

## What it does

- **Issues node certificates** for server and client authentication both,
  which mutual TLS between nodes needs (ADR-0063 clause 1) and a public
  authority no longer gives: Let's Encrypt has issued server authentication
  alone since 2026-07-08 (ADR-0033, amendment 2026-10-13).
- **Keeps its root** — a P-256 key and its self-signed certificate,
  `authority.key` and `authority.pem` — in the purpose's place; that
  certificate is the anchor every node trusts. How it is made and kept is
  the capability's, `Issuer::kept_or_made`, since 2026-10-21 when a web
  host's authority on this machine came to be kept the same way: both are
  private files (`xmip-core-secret`'s `private_file`) in a private folder;
  the key is written first, never over one, then a certificate for
  whichever key is kept, so makers racing for one folder and a crash
  between the two alike leave a matching pair (ADR-0034, amendment
  2026-10-27). Beside them the capability's register keeps every
  certificate it signs and every revocation, and the list it publishes
  (`provision::register`).
- **Signs a person's request** (`Authority::sign`, ADR-0034, amendment
  2026-10-15): an operator's certificate, client authentication alone, its
  subject the person, once the request's signature verifies and the
  `operator` purpose admits what it asks. What is signed and how is the
  capability's `Issuer`, which the surfaces reach through the runtime's
  export over the folder this keeps the root in.
- **Serves ACME** (`Serving`), so every other node obtains its certificate by
  the one protocol it would use against any authority: it names the
  authority's directory and anchor as `acme` settings. The node holding the
  authority issues its own directly (`InternalCa`). `xmip-service` serves it
  where `[provision.node]` names `serve` (ADR-0034, amendment 2026-10-22):
  the premises' own ACME service, for any standard client — the directory
  names `revokeCert` and `renewalInfo` and needs no external account;
  accounts are kept in the authority's folder (`acme/accounts/`) and
  outlive a restart; orders and authorizations say when they expire; an
  order's `replaces` (RFC 9773 section 5) is held to a certificate it
  issued, once.
- **Answers when to renew** (RFC 9773, `renewals.rs`): `renewalInfo/<id>`
  suggests from two thirds to three quarters of a certificate's life, every
  six hours; a revoked one's window has passed, so its client renews at
  once.
- **Revokes** (`revokeCert`): by the account the certificate was issued to
  (`acme/ordered/<serial>`) or signed by the certificate's own key, into the
  authority's register and its list at once.
- **Publishes** (`Publishing`, `publish`): its revocation list at `/crl` and
  its certificate at `/authority.cer` and `/authority.pem`, over plain HTTP,
  the addresses every leaf names where `published_at` is set; the same three
  answer over its ACME service's HTTPS too.
- **Validates** http-01 on the port it is configured with
  (`challenge_port`, 80 unless said) and dns-01 through a `DnsLookup` it is
  given, or by asking the DNS server on the premises `dns_server` names over
  UDP (`Resolver`, RFC 1035); an answer cut short is refused, TCP not built.

It rides on `xmip-core-provision-acme` as its carrier (ADR-0044 clause 1):
the JWS and the objects it reads are the ones the client writes. Nothing here
reaches beyond the cluster (ADR-0045).

## Verification

`tests/acme`, offline and in process: a node obtains its certificate by ACME
from the authority, by http-01 and by dns-01, and presents it on mutual TLS
to the authority's own node; a certificate is renewed at two thirds of its
life and not before; a challenge nobody answers is refused with the
authority's reason; an incomplete configuration is refused naming what is
missing; a person's request signed by the kept authority is presented on
mutual TLS to the authority's own node, and the same request is refused as a
node's. That is open problem 27's `identity-local`, without step-ca.
`tests/acme/premises.rs`: a client on the premises is told when to renew
by renewal information, revokes into the list fetched over plain HTTP, keeps
its account across a restart, and a stranger may not revoke.
`tests/acme/third_party.rs`: lego, the Go ACME client, run from where
`XMIP_ACME_LEGO` names it and SKIPPED otherwise, trusting the authority
through `LEGO_CA_CERTIFICATES` alone, obtains by http-01, is told by
renewal information it is not due, revokes, and renews at once. The
workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

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
  certificate is the anchor every node trusts.
- **Signs a person's request** (`Authority::sign`, ADR-0034, amendment
  2026-10-15): an operator's certificate, client authentication alone, its
  subject the person, once the request's signature verifies and the
  `operator` purpose admits what it asks. What is signed and how is the
  capability's `Issuer`, which the surfaces reach through the runtime's
  export over the folder this keeps the root in.
- **Serves ACME** (`Serving`), so every other node obtains its certificate by
  the one protocol it would use against any authority: it names the
  authority's directory and anchor as `acme` settings. The node holding the
  authority issues its own directly (`InternalCa`).
- **Validates** http-01 on the port it is configured with
  (`challenge_port`, 80 unless said) and dns-01 through a `DnsLookup` it is
  given; Xmip ships none yet, so without one it offers http-01 alone.

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
node's. That is open problem 27's `identity-local`, without step-ca. The
workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

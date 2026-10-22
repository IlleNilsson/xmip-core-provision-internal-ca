#![forbid(unsafe_code)]

//! The cluster's own certificate authority. A technology of
//! `xmip-core-provision`.
//!
//! **What it issues.** Node certificates for server and client
//! authentication both, which mutual TLS between nodes needs (ADR-0063
//! clause 1) and a public authority no longer gives: Let's Encrypt has
//! issued server authentication alone since 2026-07-08 (ADR-0033,
//! amendment 2026-10-13). Its root is kept in the purpose's place; the
//! anchor every node of the cluster trusts is its certificate.
//!
//! **Served over ACME** ([`Serving`]), so every node obtains its
//! certificate by the one protocol it would use against any authority: a
//! node names the authority's directory and anchor as `acme` settings. The
//! node that holds the authority issues its own directly ([`InternalCa`]).
//! The server speaks the RFC 8555 objects and JWS of `xmip-core-provision-
//! acme`, its carrier (ADR-0044 clause 1), over Xmip's own HTTP and TLS. It
//! validates http-01 on the port it is configured with, and dns-01 through
//! a [`DnsLookup`] where it is given one; Xmip ships none yet.
//!
//! **Offline.** Nothing here reaches beyond the cluster (ADR-0045).

mod authority;
mod books;
mod orders;
mod problem;
mod renewals;
mod resolver;
mod server;
mod source;
mod validation;

pub use authority::Authority;
pub use books::Policy;
pub use problem::Problem;
pub use resolver::Resolver;
pub use server::{Publishing, Serving};
pub use source::{InternalCa, SETTINGS, TECHNOLOGY};
pub use validation::DnsLookup;

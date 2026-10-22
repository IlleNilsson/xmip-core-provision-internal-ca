//! The authority served over ACME, so every node of the cluster obtains its
//! certificate by the one protocol it would use against any authority.
//!
//! HTTPS through Xmip's own TLS, the server presenting a certificate the
//! authority issued itself for the names it is reached by; a node trusts it
//! through the anchor it already holds. One connection a request, one
//! request at a time.

use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use acme::Listening;
use net::http::{Response, read_request, write_response};
use provision::{KeyPair, ProvisionError, Purpose, Result};

use crate::Authority;
use crate::books::{Books, Policy};

/// How long one connection is given.
const PATIENCE: Duration = Duration::from_secs(10);

/// The authority's ACME server, answering until dropped.
pub struct Serving {
    directory: String,
    listening: Listening,
}

impl Serving {
    /// Serve `authority` on `listen`, reached by `names` — the first is the
    /// host in its URLs, and the server presents a certificate for all —
    /// under `policy`.
    ///
    /// # Errors
    ///
    /// Where `listen` cannot be bound or the server's own certificate
    /// cannot be issued.
    pub fn start(
        authority: Arc<Authority>,
        listen: &str,
        names: &[String],
        policy: Policy,
    ) -> Result<Self> {
        let host = names
            .first()
            .ok_or_else(|| ProvisionError::new("the ACME server is reached by a name"))?;
        let key = KeyPair::generate()?;
        let now = provision::now();
        let chain = authority.issue(
            &key.public_key_info(),
            names,
            Purpose::Receive,
            now,
            now + policy.lifetime,
        )?;
        let config = tls::server_config(chain.as_bytes(), key.pem().as_bytes())
            .map(Arc::new)
            .map_err(|failure| ProvisionError::new(failure.message))?;
        let listener = TcpListener::bind(listen).map_err(|failure| {
            ProvisionError::new(format!(
                "the ACME server cannot listen on {listen}: {failure}"
            ))
        })?;
        let port = listener
            .local_addr()
            .map_err(|failure| ProvisionError::new(format!("the bound address: {failure}")))?
            .port();
        let books = Arc::new(Books::new(
            format!("https://{host}:{port}"),
            authority,
            policy,
        ));
        let directory = books.directory();
        let listening = Listening::on(listener, "the cluster authority's ACME", move |tcp| {
            answer(tcp, &config, &books);
        })?;
        Ok(Self {
            directory,
            listening,
        })
    }

    /// The directory's URL, which a node names as its ACME directory.
    #[must_use]
    pub fn directory(&self) -> &str {
        &self.directory
    }

    /// The address it listens on.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.listening.address()
    }
}

/// One connection: the handshake, one request, its answer.
fn answer(tcp: TcpStream, config: &Arc<tls::ServerConfig>, books: &Books) {
    let _ = tcp.set_read_timeout(Some(PATIENCE));
    let _ = tcp.set_write_timeout(Some(PATIENCE));
    let Ok(mut stream) = tls::server(tcp, Arc::clone(config)) else {
        return;
    };
    let Ok(Some(request)) = read_request(&mut BufReader::new(&mut stream)) else {
        return;
    };
    let _ = write_response(&mut stream, &books.answer(&request));
    stream.conn.send_close_notify();
    let _ = stream.flush();
}

/// What the authority publishes, as `GET` answers it: its revocation list
/// at `/crl`, DER, and its certificate at `/authority.cer`, DER, and
/// `/authority.pem`, PEM — the addresses its leaves name, fetched by every
/// verifier on the premises; `None` for any other path.
pub(crate) fn published(authority: &Authority, path: &str) -> Option<Response> {
    let anchor = || {
        provision::pem::decode("CERTIFICATE", authority.anchor())
            .ok()
            .and_then(|mut blocks| blocks.pop())
    };
    let (kind, body) = match path {
        provision::CRL_PATH => (
            "application/pkix-crl",
            authority.issuer().revocation_list(provision::now()).ok()?,
        ),
        provision::AUTHORITY_PATH => ("application/pkix-cert", anchor()?),
        "/authority.pem" => (
            "application/x-pem-file",
            authority.anchor().as_bytes().to_vec(),
        ),
        _ => return None,
    };
    Some(Response::new(200).header("Content-Type", kind).body(&body))
}

/// The authority's plain-HTTP publication, answering until dropped: what
/// [`published`] answers and nothing else, for a verifier that fetches a
/// revocation list before it trusts any TLS (RFC 5280 section 4.2.1.13).
pub struct Publishing {
    listening: Listening,
}

impl Publishing {
    /// Publish `authority` on `listen`.
    ///
    /// # Errors
    ///
    /// Where `listen` cannot be bound.
    pub fn start(authority: Arc<Authority>, listen: &str) -> Result<Self> {
        let listening =
            Listening::start(listen, "the cluster authority's publication", move |tcp| {
                let _ = tcp.set_read_timeout(Some(PATIENCE));
                let _ = tcp.set_write_timeout(Some(PATIENCE));
                let Ok(mut writer) = tcp.try_clone() else {
                    return;
                };
                let Ok(Some(request)) = read_request(&mut BufReader::new(tcp)) else {
                    return;
                };
                let answer = (request.method == "GET")
                    .then(|| published(&authority, &request.path))
                    .flatten()
                    .unwrap_or_else(|| Response::new(404));
                let _ = write_response(&mut writer, &answer);
            })?;
        Ok(Self { listening })
    }

    /// The address it listens on.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.listening.address()
    }
}

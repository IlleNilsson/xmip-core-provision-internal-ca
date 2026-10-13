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
use net::http::{read_request, write_response};
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

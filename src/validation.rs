//! Whether a node controls a name: what the authority checks before it
//! issues, by the challenge the node answered.

use std::io::BufReader;
use std::time::Duration;

use acme::dns01::{record_name, record_value};
use acme::http01::PREFIX;
use net::http::{Request, read_response, write_request};
use provision::{ProvisionError, Result};

/// Reads a name's TXT records, for dns-01: what a DNS client implements for
/// an authority that validates by DNS. Xmip ships none yet; an authority
/// without one offers http-01 alone.
pub trait DnsLookup: Send + Sync {
    /// Every TXT value at `name`.
    ///
    /// # Errors
    ///
    /// Where the name cannot be looked up, in words.
    fn txt(&self, name: &str) -> Result<Vec<String>>;
}

/// http-01: the answer at `name`'s `port` must be `authorization`.
///
/// # Errors
///
/// Where nothing answers, or the answer is another.
pub fn http01(name: &str, port: u16, token: &str, authorization: &str) -> Result<()> {
    let wait = Some(Duration::from_secs(10));
    let tcp = net::connect((name, port), wait).map_err(|failure| {
        ProvisionError::new(format!("http-01 found nothing at {name}:{port}: {failure}"))
    })?;
    let request = Request::new("GET", format!("{PREFIX}{token}")).header("Host", name);
    let mut writer = tcp
        .try_clone()
        .map_err(|failure| ProvisionError::new(format!("http-01: {failure}")))?;
    write_request(&mut writer, &request).map_err(|failure| ProvisionError::new(failure.message))?;
    let answer = read_response(&mut BufReader::new(tcp))
        .map_err(|failure| ProvisionError::new(failure.message))?;
    if answer.status == 200 && answer.body.trim_ascii() == authorization.as_bytes() {
        Ok(())
    } else {
        Err(ProvisionError::new(format!(
            "http-01 at {name}:{port} answered {} without the key authorization",
            answer.status
        )))
    }
}

/// dns-01: a TXT record at the name's challenge record must hold the
/// digest of `authorization`.
///
/// # Errors
///
/// Where the lookup fails, or no record holds it.
pub fn dns01(lookup: &dyn DnsLookup, name: &str, authorization: &str) -> Result<()> {
    let record = record_name(name);
    let wanted = record_value(authorization);
    if lookup.txt(&record)?.contains(&wanted) {
        Ok(())
    } else {
        Err(ProvisionError::new(format!(
            "dns-01 found no TXT record at {record} holding the key authorization"
        )))
    }
}

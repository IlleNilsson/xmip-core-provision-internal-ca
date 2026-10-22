//! dns-01 checked against a DNS server on the premises: the TXT records at
//! a name, asked of the one server the authority is configured with
//! (`dns_server`), over UDP (RFC 1035 sections 4.1 and 4.2.1). A node
//! behind a firewall proves a name by the record its DNS provider's module
//! wrote to the premises' own DNS, and nothing reaches beyond the cluster
//! (ADR-0045).
//!
//! One question, one answer: recursion is asked for, an answer is matched
//! to its question by its identifier and its question, and one cut short
//! (`TC`) is refused in words rather than asked again over TCP, which is
//! not built.

use std::net::UdpSocket;
use std::time::Duration;

use provision::{ProvisionError, Result};

use crate::DnsLookup;

/// How long the server is given to answer.
const PATIENCE: Duration = Duration::from_secs(2);

/// The TXT type and the Internet class.
const TXT: u16 = 16;
const INTERNET: u16 = 1;

/// The largest answer read over UDP without EDNS (RFC 1035 section 2.3.4).
const LARGEST: usize = 512;

/// The DNS server on the premises dns-01 is checked against.
#[derive(Clone, Debug)]
pub struct Resolver {
    server: String,
}

impl Resolver {
    /// Ask `server`, `host:port`.
    #[must_use]
    pub fn new(server: &str) -> Self {
        Self {
            server: server.to_string(),
        }
    }
}

impl DnsLookup for Resolver {
    fn txt(&self, name: &str) -> Result<Vec<String>> {
        let said = |what: String| ProvisionError::new(format!("dns-01 at {}: {what}", self.server));
        let socket = UdpSocket::bind(if self.server.starts_with('[') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
        .map_err(|failure| said(failure.to_string()))?;
        socket
            .set_read_timeout(Some(PATIENCE))
            .map_err(|failure| said(failure.to_string()))?;
        let identifier = u16::from_be_bytes(codec::random::array::<2>());
        let question = question(name)?;
        socket
            .send_to(&query(identifier, &question), &self.server)
            .map_err(|failure| said(failure.to_string()))?;
        let mut answer = [0u8; LARGEST];
        let length = socket
            .recv(&mut answer)
            .map_err(|failure| said(format!("no answer: {failure}")))?;
        read_answer(&answer[..length], identifier, &question)
            .map_err(|failure| said(failure.message))
    }
}

/// The question for `name`'s TXT records, as the wire writes it.
fn question(name: &str) -> Result<Vec<u8>> {
    let mut written = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        let length = u8::try_from(label.len())
            .ok()
            .filter(|length| (1..=63).contains(length))
            .ok_or_else(|| ProvisionError::new(format!("{name:?} is not a DNS name")))?;
        written.push(length);
        written.extend_from_slice(label.as_bytes());
    }
    written.push(0);
    written.extend_from_slice(&TXT.to_be_bytes());
    written.extend_from_slice(&INTERNET.to_be_bytes());
    Ok(written)
}

/// A query: the header, recursion desired, and one question.
fn query(identifier: u16, question: &[u8]) -> Vec<u8> {
    let mut written = identifier.to_be_bytes().to_vec();
    written.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    written.extend_from_slice(question);
    written
}

/// Every TXT value an answer holds, each record's strings joined.
fn read_answer(answer: &[u8], identifier: u16, question: &[u8]) -> Result<Vec<String>> {
    let short = || ProvisionError::new("the answer ends early");
    let header = answer.get(..12).ok_or_else(short)?;
    if u16::from_be_bytes([header[0], header[1]]) != identifier
        || answer.get(12..12 + question.len()) != Some(question)
    {
        return Err(ProvisionError::new("the answer is to another question"));
    }
    if header[2] & 0x02 != 0 {
        return Err(ProvisionError::new(
            "the answer was cut short and TCP is not asked",
        ));
    }
    match header[3] & 0x0f {
        0 | 3 => {}
        code => {
            return Err(ProvisionError::new(format!(
                "the server answered code {code}"
            )));
        }
    }
    let count = u16::from_be_bytes([header[6], header[7]]);
    let mut at = 12 + question.len();
    let mut values = Vec::new();
    for _ in 0..count {
        at = skip_name(answer, at).ok_or_else(short)?;
        let fixed = answer.get(at..at + 10).ok_or_else(short)?;
        let kind = u16::from_be_bytes([fixed[0], fixed[1]]);
        let length = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let data = answer.get(at + 10..at + 10 + length).ok_or_else(short)?;
        at += 10 + length;
        if kind == TXT {
            values.push(strings(data).ok_or_else(short)?);
        }
    }
    Ok(values)
}

/// Where the name at `at` ends: its labels, or a pointer to another.
fn skip_name(answer: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let length = *answer.get(at)?;
        match length {
            0 => return Some(at + 1),
            _ if length & 0xc0 == 0xc0 => return Some(at + 2),
            _ => at += 1 + usize::from(length),
        }
    }
}

/// A TXT record's character strings, joined.
fn strings(mut data: &[u8]) -> Option<String> {
    let mut joined = Vec::new();
    while let Some((&length, rest)) = data.split_first() {
        let length = usize::from(length);
        joined.extend_from_slice(rest.get(..length)?);
        data = &rest[length..];
    }
    Some(String::from_utf8_lossy(&joined).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DNS server on loopback answering one question with `values`.
    fn serving(values: &'static [&'static str]) -> String {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bound");
        let address = socket.local_addr().expect("address").to_string();
        std::thread::spawn(move || {
            let mut asked = [0u8; LARGEST];
            let (length, from) = socket.recv_from(&mut asked).expect("asked");
            let mut answer = asked[..length].to_vec();
            answer[2] = 0x81;
            answer[3] = 0x80;
            answer[7] = u8::try_from(values.len()).expect("few");
            for value in values {
                answer.extend_from_slice(&[0xc0, 12]);
                answer.extend_from_slice(&TXT.to_be_bytes());
                answer.extend_from_slice(&INTERNET.to_be_bytes());
                answer.extend_from_slice(&[0, 0, 0, 60]);
                let length = u16::try_from(value.len() + 1).expect("short");
                answer.extend_from_slice(&length.to_be_bytes());
                answer.push(u8::try_from(value.len()).expect("short"));
                answer.extend_from_slice(value.as_bytes());
            }
            socket.send_to(&answer, from).expect("answered");
        });
        address
    }

    #[test]
    fn the_txt_records_at_a_name_are_read_from_the_server_asked() {
        let server = serving(&["first", "second"]);
        let values = Resolver::new(&server)
            .txt("_acme-challenge.r1.example")
            .expect("answered");
        assert_eq!(values, ["first", "second"]);
        assert!(question("bad..name").is_err());
        assert_eq!(strings(&[2, b'a', b'b', 1, b'c']).as_deref(), Some("abc"));
    }
}

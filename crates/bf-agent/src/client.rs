//! A small blocking HTTP/1.1 client for talking to an agent. `bf-agent probe` uses it to
//! check the service on the node itself, and the tests use it against a real socket.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use bf_common::sign::{Parts, hex, sign};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Fresh random text for the `X-BF-Nonce` header: 32 hex characters from the system.
pub fn random_nonce() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex(&bytes))
}

/// Signs `parts` with `secret`, sends it to the agent at `addr` and returns the status
/// code and body of the answer.
pub fn request(addr: SocketAddr, secret: &[u8], parts: &Parts<'_>) -> io::Result<(u16, String)> {
    let head = format!(
        "{} {} HTTP/1.1\r\nHost: {addr}\r\nX-BF-Time: {}\r\nX-BF-Nonce: {}\r\nX-BF-Sig: {}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        parts.method,
        parts.path_and_query,
        parts.time,
        parts.nonce,
        sign(secret, parts),
        parts.body.len()
    );
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.write_all(head.as_bytes())?;
    stream.write_all(parts.body)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> io::Result<(u16, String)> {
    let invalid = |what| io::Error::new(io::ErrorKind::InvalidData, what);
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| invalid("no end of headers"))?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| invalid("bad status line"))?;
    Ok((status, body.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_32_hex_characters_and_never_repeat() {
        let first = random_nonce().unwrap();
        let second = random_nonce().unwrap();

        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }
}

//! A small HTTPS server and a certificate maker for tests: a test CA (root, optionally an
//! intermediate, like Caddy's), leaves for chosen names, and a blocking server that
//! hands each request to a closure. It is compiled into the library's unit tests and into
//! the integration tests, which both include this one file.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A certificate authority that can sign leaves (and, for a root, an intermediate).
pub struct Authority {
    params: CertificateParams,
    key: KeyPair,
    cert: rcgen::Certificate,
    is_intermediate: bool,
}

/// A server certificate: the chain to present (leaf first) and its private key.
pub struct Leaf {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2090, 1, 1);
    params
}

impl Authority {
    pub fn root(common_name: &str) -> Authority {
        let params = ca_params(common_name);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Authority {
            params,
            key,
            cert,
            is_intermediate: false,
        }
    }

    /// A CA signed by this one, like the intermediate Caddy's local CA signs leaves with.
    pub fn intermediate(&self, common_name: &str) -> Authority {
        let params = ca_params(common_name);
        let key = KeyPair::generate().unwrap();
        let issuer = Issuer::from_params(&self.params, &self.key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        Authority {
            params,
            key,
            cert,
            is_intermediate: true,
        }
    }

    /// The certificate as PEM: what goes into `<node>.pem`.
    pub fn pem(&self) -> String {
        self.cert.pem()
    }

    /// A leaf for these names, valid now. `expired` makes one that ended in 2021.
    pub fn leaf(&self, names: &[&str], expired: bool) -> Leaf {
        let mut params =
            CertificateParams::new(names.iter().map(ToString::to_string).collect::<Vec<_>>())
                .unwrap();
        params.distinguished_name.push(DnType::CommonName, names[0]);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        if expired {
            params.not_before = date_time_ymd(2020, 1, 1);
            params.not_after = date_time_ymd(2021, 1, 1);
        } else {
            params.not_before = date_time_ymd(2020, 1, 1);
            params.not_after = date_time_ymd(2090, 1, 1);
        }
        let key = KeyPair::generate().unwrap();
        let issuer = Issuer::from_params(&self.params, &self.key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        let mut chain = vec![cert.der().clone()];
        if self.is_intermediate {
            chain.push(self.cert.der().clone());
        }
        Leaf {
            chain,
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        }
    }
}

/// A self-signed leaf for these names (no authority above it).
pub fn self_signed_leaf(names: &[&str]) -> Leaf {
    let params =
        CertificateParams::new(names.iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    Leaf {
        chain: vec![cert.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    }
}

/// One request as the test server read it.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The server name the client asked for in the TLS handshake (`None` for plain HTTP).
    pub sni: Option<String>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }
}

pub type Handler = Arc<dyn Fn(&Request) -> Response + Send + Sync>;

/// A server on `127.0.0.1` that answers every request with the handler.
pub struct Server {
    pub addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Server {
    /// Speaks TLS with `leaf`.
    pub fn tls(leaf: Leaf, handler: Handler) -> Server {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(leaf.chain, leaf.key)
        .unwrap();
        Self::start(Some(Arc::new(config)), handler)
    }

    /// Speaks plain HTTP, which a client that insists on HTTPS must never reach.
    pub fn plain(handler: Handler) -> Server {
        Self::start(None, handler)
    }

    fn start(config: Option<Arc<rustls::ServerConfig>>, handler: Handler) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, halt) = (requests.clone(), stop.clone());
        thread::spawn(move || {
            for stream in listener.incoming() {
                if halt.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let (config, handler, seen) = (config.clone(), handler.clone(), seen.clone());
                thread::spawn(move || {
                    let _ = serve_one(stream, config, handler, seen);
                });
            }
        });
        Server {
            addr,
            requests,
            stop,
        }
    }

    /// How many requests reached the handler.
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

fn serve_one(
    tcp: TcpStream,
    config: Option<Arc<rustls::ServerConfig>>,
    handler: Handler,
    seen: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
    match config {
        Some(config) => {
            let connection = rustls::ServerConnection::new(config)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let mut stream = rustls::StreamOwned::new(connection, tcp);
            // The handshake happens on the first read.
            let request = read_request(&mut stream, true)?;
            seen.fetch_add(1, Ordering::SeqCst);
            let response = handler(&request);
            write_response(&mut stream, &response)?;
            stream.conn.send_close_notify();
            let _ = stream.flush();
            Ok(())
        }
        None => {
            let mut stream = tcp;
            let request = read_request(&mut stream, false)?;
            seen.fetch_add(1, Ordering::SeqCst);
            let response = handler(&request);
            write_response(&mut stream, &response)
        }
    }
}

trait SniSource {
    fn sni(&self) -> Option<String>;
}
impl SniSource for rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    fn sni(&self) -> Option<String> {
        self.conn.server_name().map(str::to_string)
    }
}
impl SniSource for TcpStream {
    fn sni(&self) -> Option<String> {
        None
    }
}

fn read_request<S: Read + SniSource>(stream: &mut S, _tls: bool) -> std::io::Result<Request> {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        if raw.len() > 64 * 1024 {
            return Err(std::io::Error::other("head too long"));
        }
        if stream.read(&mut byte)? == 0 {
            return Err(std::io::Error::other("closed"));
        }
        raw.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&raw).to_string();
    let mut lines = head.lines();
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split(' ');
    let (method, path) = (
        parts.next().unwrap_or_default().to_string(),
        parts.next().unwrap_or_default().to_string(),
    );
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    let length = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    Ok(Request {
        method,
        path,
        headers,
        body,
        sni: stream.sni(),
    })
}

fn write_response<S: Write>(stream: &mut S, response: &Response) -> std::io::Result<()> {
    let chunked = response
        .headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("transfer-encoding") && v == "chunked");
    let mut head = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", response.status);
    if !chunked {
        head.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
    }
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    if chunked {
        // One chunk, then the end: the client learns the size only by reading it.
        stream.write_all(format!("{:x}\r\n", response.body.len()).as_bytes())?;
        stream.write_all(&response.body)?;
        stream.write_all(b"\r\n0\r\n\r\n")?;
    } else {
        stream.write_all(&response.body)?;
    }
    stream.flush()
}

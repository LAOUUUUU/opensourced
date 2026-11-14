//! One node as the poller sees it: the two files that identify it, a signed request, and
//! the pinned HTTPS connection to its agent (`specs/poller.md`, `specs/agent.md`).
//!
//! The signing and the reading of answers live in [`Link`], above a [`Transport`] that
//! only moves bytes. The real transport is [`HttpsTransport`]; tests put the real agent
//! behind a fake one.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bf_common::peers::{PeerList, is_valid_key};
use bf_common::sign::{Parts, hex, sign, unhex};
use serde::Deserialize;

use crate::nodes::check_node_name;
use crate::secrets::{KeyError, random_bytes, read_secret_text};
use crate::store::is_unsafe_in_text;

/// The name a node's certificate is for is `<name>.agent.internal` (decision 006).
pub const DOMAIN: &str = "agent.internal";
/// A status answer may be this big (a peer is about 150 bytes, so thousands fit).
pub const STATUS_CAP: usize = 2 * 1024 * 1024;
/// Every other answer is small.
pub const ANSWER_CAP: usize = 64 * 1024;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ---- the node's files ----

/// What the two files in the nodes directory hold. Kept out of `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeFiles {
    secret: Vec<u8>,
    root_pem: Vec<u8>,
}

impl NodeFiles {
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub fn root_pem(&self) -> &[u8] {
        &self.root_pem
    }

    /// Whether the root file can be trusted as a pin: one or two PEM certificates a client
    /// can be built from.
    pub fn check_root(&self) -> Result<(), FilesProblem> {
        pinned_client(&self.root_pem, "x", None, Timeouts::default()).map(drop)
    }
}

impl fmt::Debug for NodeFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeFiles").finish_non_exhaustive()
    }
}

/// Why a node's files cannot be used. Never holds what a file contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesProblem {
    SecretMissing,
    /// Not private, not a file, too big, not text, or the disk refused.
    SecretUnusable(String),
    SecretNotHex,
    SecretTooShort,
    RootMissing,
    RootUnusable,
}

impl fmt::Display for FilesProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretMissing => f.write_str("the secret file is missing"),
            Self::SecretUnusable(why) => write!(f, "the secret file is unusable: {why}"),
            Self::SecretNotHex => f.write_str("the secret file does not hold hex"),
            Self::SecretTooShort => {
                f.write_str("the secret must be at least 32 bytes (64 hex characters)")
            }
            Self::RootMissing => f.write_str("the root certificate file is missing"),
            Self::RootUnusable => {
                f.write_str("the root certificate file is not one or two PEM certificates")
            }
        }
    }
}

impl std::error::Error for FilesProblem {}

/// Reads `<dir>/<name>.secret` and `<dir>/<name>.pem`. The secret must be private to its
/// owner (the rules of the other key files) and at least 32 bytes of hex; the root must
/// be one or two PEM certificates.
pub fn read_files(dir: &Path, name: &str) -> Result<NodeFiles, FilesProblem> {
    let files = read_files_unchecked(dir, name)?;
    files.check_root()?;
    Ok(files)
}

/// [`read_files`] without the last step, the check that the root file is usable
/// ([`NodeFiles::check_root`]). That check builds a whole TLS client, so the poller makes it
/// only for files that differ from the ones it already has a link for.
pub fn read_files_unchecked(dir: &Path, name: &str) -> Result<NodeFiles, FilesProblem> {
    // A name is checked when a node is registered; check it again before it becomes part
    // of a path, so nothing here can be walked out of the directory.
    if check_node_name(name).is_err() {
        return Err(FilesProblem::SecretMissing);
    }
    let text = read_secret_text(&dir.join(format!("{name}.secret"))).map_err(|e| match e {
        KeyError::Missing => FilesProblem::SecretMissing,
        other => FilesProblem::SecretUnusable(other.to_string()),
    })?;
    let secret = unhex(text.trim()).ok_or(FilesProblem::SecretNotHex)?;
    if secret.len() < 32 {
        return Err(FilesProblem::SecretTooShort);
    }
    let root_path = dir.join(format!("{name}.pem"));
    let root_pem = match std::fs::metadata(&root_path) {
        Ok(meta) if meta.is_file() && meta.len() <= MAX_ROOT_BYTES => {
            std::fs::read(&root_path).map_err(|_| FilesProblem::RootUnusable)?
        }
        Ok(_) => return Err(FilesProblem::RootUnusable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FilesProblem::RootMissing);
        }
        Err(_) => return Err(FilesProblem::RootUnusable),
    };
    Ok(NodeFiles { secret, root_pem })
}

/// A root file bigger than this is not a root.
const MAX_ROOT_BYTES: u64 = 64 * 1024;

/// A client that trusts only the certificates in `root_pem` (one or two), and, when an
/// address is given, connects `<name>.agent.internal` to it. Redirects, proxies and plain
/// HTTP are off. `tls_certs_only` drops every built-in and system root (checked in
/// reqwest 0.13.5's source): the pin is not added to a public store, it is the store.
fn pinned_client(
    root_pem: &[u8],
    name: &str,
    address: Option<SocketAddr>,
    timeouts: Timeouts,
) -> Result<reqwest::Client, FilesProblem> {
    let certs =
        reqwest::Certificate::from_pem_bundle(root_pem).map_err(|_| FilesProblem::RootUnusable)?;
    if !(1..=2).contains(&certs.len()) {
        return Err(FilesProblem::RootUnusable);
    }
    let mut builder = reqwest::Client::builder()
        .tls_certs_only(certs)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .http1_only()
        .connect_timeout(timeouts.connect)
        .timeout(timeouts.total)
        // Shorter than Caddy's 30 second idle limit, so a connection it has already closed
        // is not picked for the next request.
        .pool_idle_timeout(Duration::from_secs(20));
    if let Some(address) = address {
        builder = builder.resolve(&format!("{name}.{DOMAIN}"), address);
    }
    builder.build().map_err(|_| FilesProblem::RootUnusable)
}

// ---- what can go wrong with a call ----

/// Why a call to a node did not give the answer wanted. The text is for the admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkProblem {
    /// The node's certificate was not accepted: not signed by the pinned root, for another
    /// name, or out of date.
    Certificate,
    /// Nothing to talk to: no route, refused, reset.
    Unreachable,
    /// No answer in time.
    Timeout,
    /// The answer was far bigger than an agent sends.
    TooLarge,
    /// Any other failure of the connection.
    Connection,
    /// The node answered 200 with something that is not what an agent sends.
    BadAnswer,
    /// 404: the agent's one answer to a bad signature, a clock off by more than 60 seconds
    /// and a request older than its replay mark.
    Refused,
    /// 503: the agent cannot read or change WireGuard.
    Unavailable,
    /// 409: the node holds a newer list, or another one under the same version.
    Stale { stored: Option<u64> },
    /// 400 with a reason: our list failed the agent's checks. The detail names a position,
    /// never an entry.
    BadList { detail: String },
    /// 400 without a reason.
    BadRequest,
    /// Any other status.
    Server(u16),
}

impl fmt::Display for LinkProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate => f.write_str(
                "its certificate was not accepted (wrong root file, wrong name, or the node was reinstalled)",
            ),
            Self::Unreachable => {
                f.write_str("cannot connect (node down, wrong address, or the port is closed)")
            }
            Self::Timeout => f.write_str("no answer in time"),
            Self::TooLarge => f.write_str("the answer was far bigger than an agent sends"),
            Self::Connection => f.write_str("the connection failed"),
            Self::BadAnswer => f.write_str("the answer was not what an agent sends"),
            Self::Refused => f.write_str(
                "refused: wrong secret, clocks more than 60 seconds apart, or a request older than the agent's replay mark",
            ),
            Self::Unavailable => f.write_str("the agent cannot read or change WireGuard"),
            Self::Stale { stored: Some(v) } => {
                write!(f, "the node holds a newer or different list (its version is {v})")
            }
            Self::Stale { stored: None } => f.write_str("the node holds a newer or different list"),
            Self::BadList { detail } => write!(f, "the node refused the list: {detail}"),
            Self::BadRequest => f.write_str("the node did not understand the request"),
            Self::Server(code) => write!(f, "the node answered {code}"),
        }
    }
}

impl std::error::Error for LinkProblem {}

// ---- what the node says ----

/// What `GET /v1/status` told us. The client addresses it carries are dropped on reading.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeReading {
    /// The node's WireGuard server public key (public, and what a device's config needs).
    pub wg_public_key: String,
    pub listen_port: u16,
    pub online: u64,
    pub peers_total: u64,
    /// The version of the list the node holds, `None` when it has never been given one.
    pub desired_version: Option<u64>,
    pub load1: Option<f64>,
    pub peers: Vec<PeerReading>,
    /// The node's recent SSH logins, `None` from an agent that does not report them. Each one
    /// passed [`safe_login`]; the rest were dropped.
    pub logins: Option<Vec<bf_common::logins::Login>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerReading {
    pub public_key: String,
    pub online: bool,
    pub handshake_age: Option<u64>,
    pub rx: u64,
    pub tx: u64,
}

/// What a `PUT /v1/peers` that was accepted did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Pushed {
    pub version: u64,
    pub added: u64,
    pub removed: u64,
    pub updated: u64,
}

// ---- moving bytes ----

/// A signed request, ready to send.
#[derive(Debug, Clone, Copy)]
pub struct Outgoing<'a> {
    pub method: &'static str,
    pub path: &'static str,
    pub time: u64,
    pub nonce: &'a str,
    pub signature: &'a str,
    pub body: &'a [u8],
    /// Answers longer than this are refused (`LinkProblem::TooLarge`).
    pub cap: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Moves a signed request to the node and the answer back. It adds the three `X-BF-`
/// headers and nothing else of ours; it signs nothing and reads no JSON.
pub trait Transport: Send + Sync {
    fn send<'a>(&'a self, out: Outgoing<'a>) -> BoxFuture<'a, Result<Incoming, LinkProblem>>;
}

/// How long the real connection may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub connect: Duration,
    pub total: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect: Duration::from_secs(3),
            total: Duration::from_secs(8),
        }
    }
}

/// HTTPS to one node: trusts only that node's root, connects to its registered address and
/// sends `<name>.agent.internal` as the name to check and as SNI.
pub struct HttpsTransport {
    client: reqwest::Client,
    base: String,
}

impl HttpsTransport {
    pub fn new(name: &str, address: SocketAddr, root_pem: &[u8]) -> Result<Self, FilesProblem> {
        Self::with_timeouts(name, address, root_pem, Timeouts::default())
    }

    pub fn with_timeouts(
        name: &str,
        address: SocketAddr,
        root_pem: &[u8],
        timeouts: Timeouts,
    ) -> Result<Self, FilesProblem> {
        Ok(HttpsTransport {
            client: pinned_client(root_pem, name, Some(address), timeouts)?,
            base: format!("https://{name}.{DOMAIN}:{}", address.port()),
        })
    }
}

/// Sorts a failed request into the few kinds an admin can act on.
fn classify(error: &reqwest::Error) -> LinkProblem {
    if error.is_timeout() {
        return LinkProblem::Timeout;
    }
    let mut chain = String::new();
    let mut next: Option<&dyn std::error::Error> = Some(error);
    while let Some(link) = next {
        chain.push_str(&link.to_string().to_lowercase());
        chain.push(' ');
        next = link.source();
    }
    if chain.contains("certificate") || chain.contains("unknownissuer") {
        LinkProblem::Certificate
    } else if error.is_connect() {
        LinkProblem::Unreachable
    } else {
        LinkProblem::Connection
    }
}

impl Transport for HttpsTransport {
    fn send<'a>(&'a self, out: Outgoing<'a>) -> BoxFuture<'a, Result<Incoming, LinkProblem>> {
        Box::pin(async move {
            let method = reqwest::Method::from_bytes(out.method.as_bytes())
                .map_err(|_| LinkProblem::Connection)?;
            let mut request = self
                .client
                .request(method, format!("{}{}", self.base, out.path))
                .header("X-BF-Time", out.time.to_string())
                .header("X-BF-Nonce", out.nonce)
                .header("X-BF-Sig", out.signature);
            if !out.body.is_empty() {
                request = request
                    .header("Content-Type", "application/json")
                    .body(out.body.to_vec());
            }
            let mut response = request.send().await.map_err(|e| classify(&e))?;
            let status = response.status().as_u16();
            if response
                .content_length()
                .is_some_and(|length| length > out.cap as u64)
            {
                return Err(LinkProblem::TooLarge);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|e| classify(&e))? {
                if body.len() + chunk.len() > out.cap {
                    return Err(LinkProblem::TooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Incoming { status, body })
        })
    }
}

// ---- the link ----

/// Signs requests to one node and reads its answers.
pub struct Link {
    transport: Arc<dyn Transport>,
    secret: Vec<u8>,
    /// The time of the last request, so the next one is signed strictly later.
    last_time: Mutex<u64>,
}

impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Link").finish_non_exhaustive()
    }
}

impl Link {
    pub fn new(transport: Arc<dyn Transport>, secret: Vec<u8>) -> Link {
        Link {
            transport,
            secret,
            last_time: Mutex::new(0),
        }
    }

    /// The time of the last request this link signed (0 before any).
    pub fn last_time(&self) -> u64 {
        *self
            .last_time
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// This link, continuing after `time`: its next request is signed later than that. A
    /// link built to replace another (a new secret file) keeps the node's times rising.
    pub fn starting_after(self, time: u64) -> Link {
        *self
            .last_time
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = time;
        self
    }

    /// The time for the next request: `now`, or one second after the last request if that
    /// is not later. A restarted agent refuses requests signed at or before its replay
    /// mark (decision 007), so every request to a node must be signed later than the
    /// one before it.
    fn next_time(&self, now: u64) -> u64 {
        let mut last = self
            .last_time
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let time = if now > *last {
            now
        } else {
            last.saturating_add(1)
        };
        *last = time;
        time
    }

    async fn call(
        &self,
        method: &'static str,
        path: &'static str,
        body: &[u8],
        cap: usize,
        now: u64,
    ) -> Result<Incoming, LinkProblem> {
        let time = self.next_time(now);
        let nonce = hex(&random_bytes::<16>().map_err(|_| LinkProblem::Connection)?);
        let signature = sign(
            &self.secret,
            &Parts {
                method,
                path_and_query: path,
                time,
                nonce: &nonce,
                body,
            },
        );
        self.transport
            .send(Outgoing {
                method,
                path,
                time,
                nonce: &nonce,
                signature: &signature,
                body,
                cap,
            })
            .await
    }

    /// `GET /v1/status`, signed at `now` or later.
    pub async fn status(&self, now: u64) -> Result<NodeReading, LinkProblem> {
        let answer = self.call("GET", "/v1/status", &[], STATUS_CAP, now).await?;
        match answer.status {
            200 => {
                let wire: StatusWire =
                    serde_json::from_slice(&answer.body).map_err(|_| LinkProblem::BadAnswer)?;
                NodeReading::try_from(wire).map_err(|()| LinkProblem::BadAnswer)
            }
            404 => Err(LinkProblem::Refused),
            503 => Err(LinkProblem::Unavailable),
            code => Err(LinkProblem::Server(code)),
        }
    }

    /// `PUT /v1/peers` with `list`, signed at `now` or later.
    pub async fn put_peers(&self, now: u64, list: &PeerList) -> Result<Pushed, LinkProblem> {
        let body = serde_json::to_vec(list).map_err(|_| LinkProblem::BadRequest)?;
        let answer = self
            .call("PUT", "/v1/peers", &body, ANSWER_CAP, now)
            .await?;
        match answer.status {
            200 => serde_json::from_slice(&answer.body).map_err(|_| LinkProblem::BadAnswer),
            404 => Err(LinkProblem::Refused),
            503 => Err(LinkProblem::Unavailable),
            409 => Err(LinkProblem::Stale {
                stored: json_field(&answer.body, "stored_version").and_then(|v| v.as_u64()),
            }),
            400 => match json_field(&answer.body, "error") {
                Some(kind) if kind.as_str() == Some("bad_list") => Err(LinkProblem::BadList {
                    detail: json_field(&answer.body, "detail")
                        .and_then(|d| d.as_str().map(tidy))
                        .unwrap_or_default(),
                }),
                _ => Err(LinkProblem::BadRequest),
            },
            code => Err(LinkProblem::Server(code)),
        }
    }
}

fn json_field(body: &[u8], name: &str) -> Option<serde_json::Value> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get(name)
        .cloned()
}

/// A reason from a node, as plain short text: no control characters, at most 120.
fn tidy(text: &str) -> String {
    text.chars()
        .filter(|c| !is_unsafe_in_text(*c))
        .take(120)
        .collect()
}

/// The part of the agent's status we use. Unknown fields (and the masked client address
/// every peer carries) are ignored, so a newer agent still reads.
#[derive(Deserialize)]
struct StatusWire {
    interface: InterfaceWire,
    online: u64,
    peers_total: u64,
    #[serde(default)]
    desired_version: Option<u64>,
    #[serde(default)]
    load1: Option<f64>,
    peers: Vec<PeerWire>,
    /// Read one by one, so a malformed login drops itself, not the whole reading.
    #[serde(default)]
    logins: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
struct InterfaceWire {
    public_key: String,
    listen_port: u16,
}

#[derive(Deserialize)]
struct PeerWire {
    public_key: String,
    online: bool,
    #[serde(default)]
    handshake_age: Option<u64>,
    rx: u64,
    tx: u64,
}

/// A node is trusted to sign its answers' meaning, not to send text that is safe to print or to
/// put in a client's configuration: every key must be a canonical WireGuard key, or the whole
/// answer is refused.
impl TryFrom<StatusWire> for NodeReading {
    type Error = ();

    fn try_from(wire: StatusWire) -> Result<NodeReading, ()> {
        if !is_valid_key(&wire.interface.public_key)
            || !wire.peers.iter().all(|p| is_valid_key(&p.public_key))
        {
            return Err(());
        }
        Ok(NodeReading {
            wg_public_key: wire.interface.public_key,
            listen_port: wire.interface.listen_port,
            online: wire.online,
            peers_total: wire.peers_total,
            desired_version: wire.desired_version,
            load1: wire.load1,
            peers: wire
                .peers
                .into_iter()
                .map(|p| PeerReading {
                    public_key: p.public_key,
                    online: p.online,
                    handshake_age: p.handshake_age,
                    rx: p.rx,
                    tx: p.tx,
                })
                .collect(),
            logins: wire
                .logins
                .map(|items| items.into_iter().filter_map(safe_login).collect()),
        })
    }
}

/// A login as the node sent it, if it is safe to keep and to put in an email: a plain user
/// name, an address, a `SHA256:` fingerprint of the right shape (or none, for a password),
/// and a key name stripped of control and direction characters and cut to 80.
fn safe_login(value: serde_json::Value) -> Option<bf_common::logins::Login> {
    safe(serde_json::from_value(value).ok()?)
}

/// The same check for a login read on the VM itself.
pub(crate) fn safe(mut login: bf_common::logins::Login) -> Option<bf_common::logins::Login> {
    let user_ok = (1..=32).contains(&login.user.len())
        && login
            .user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    let key_ok = login.key.as_deref().is_none_or(|key| {
        key.strip_prefix("SHA256:").is_some_and(|fp| {
            fp.len() == 43
                && fp
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        })
    });
    if !user_ok || !key_ok {
        return None;
    }
    login.from = login.from.to_canonical();
    login.key_name = login.key_name.map(|name| {
        name.chars()
            .filter(|c| !is_unsafe_in_text(*c))
            .take(80)
            .collect()
    });
    Some(login)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bf_common::peers::PeerSpec;
    use bf_common::sign::{Refusal, Verifier};
    use bf_common::status::{PeerStatus, Status, mask_endpoint};
    use bf_common::wg::InterfaceInfo;

    use crate::testtls::{Authority, Handler, Response, Server, self_signed_leaf};

    const SECRET_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const OTHER_SECRET_HEX: &str =
        "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    const K1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const K2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const NODE_KEY: &str = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=";

    fn secret() -> Vec<u8> {
        unhex(SECRET_HEX).unwrap()
    }

    fn reading_of(value: serde_json::Value) -> NodeReading {
        NodeReading::try_from(serde_json::from_value::<StatusWire>(value).unwrap()).unwrap()
    }

    #[test]
    fn logins_in_a_status_are_read_and_unsafe_ones_are_dropped_one_by_one() {
        let mut value: serde_json::Value = serde_json::from_str(&status_json()).unwrap();
        assert_eq!(
            reading_of(value.clone()).logins,
            None,
            "an old agent reports none"
        );
        let fp = "SHA256:HvjXAIbzUdF23SQNP93/235ibkdyPOxPOROYgxD3Tjs";
        value["logins"] = serde_json::json!([
            {"at": 10, "user": "root", "from": "203.0.113.7", "key": fp, "key_name": "lao-mac"},
            {"at": 11, "user": "bf-backup", "from": "2001:db8::1", "key": null},
            {"at": 12, "user": "ro\not", "from": "203.0.113.7", "key": null},
            {"at": 13, "user": "root", "from": "203.0.113.7", "key": "SHA256:<b>"},
            {"at": 14, "user": "root", "from": "not an address", "key": null},
            {"at": "soon", "user": "root", "from": "203.0.113.7"},
            {"at": 15, "user": "root", "from": "203.0.113.7", "key": null, "key_name": "evil\u{202e}name\nX"},
            {"at": 16, "user": "x".repeat(40), "from": "203.0.113.7", "key": null}
        ]);
        let logins = reading_of(value).logins.unwrap();
        let ats: Vec<u64> = logins.iter().map(|l| l.at).collect();
        assert_eq!(
            ats,
            [10, 11, 15],
            "the malformed and unsafe ones are dropped"
        );
        assert_eq!(logins[0].key.as_deref(), Some(fp));
        assert_eq!(logins[0].key_name.as_deref(), Some("lao-mac"));
        assert_eq!(
            logins[1].from,
            "2001:db8::1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            logins[2].key_name.as_deref(),
            Some("evilnameX"),
            "no control or direction marks"
        );
    }

    fn status_json() -> String {
        let status = Status {
            time: 1_000,
            interface: InterfaceInfo {
                public_key: NODE_KEY.to_string(),
                listen_port: 51820,
            },
            online: 1,
            peers_total: 2,
            desired_version: Some(7),
            load1: Some(0.25),
            peers: vec![
                PeerStatus {
                    public_key: K1.to_string(),
                    allowed_ips: vec!["10.77.0.2/32".to_string()],
                    handshake_age: Some(12),
                    online: true,
                    rx: 100,
                    tx: 200,
                    endpoint: Some(mask_endpoint("203.0.113.77".parse().unwrap())),
                },
                PeerStatus {
                    public_key: K2.to_string(),
                    allowed_ips: vec!["10.77.0.3/32".to_string()],
                    handshake_age: None,
                    online: false,
                    rx: 0,
                    tx: 0,
                    endpoint: None,
                },
            ],
            logins: None,
        };
        serde_json::to_string(&status).unwrap()
    }

    fn list() -> PeerList {
        PeerList {
            version: 7,
            peers: vec![PeerSpec {
                public_key: K1.to_string(),
                allowed_ips: vec!["10.77.0.2/32".to_string()],
                trackers: true,
            }],
        }
    }

    /// What a call carried, as the transport saw it.
    #[derive(Debug, Clone)]
    struct Seen {
        method: &'static str,
        path: &'static str,
        time: u64,
        nonce: String,
        body: Vec<u8>,
        cap: usize,
        verdict: Result<(), Refusal>,
    }

    /// Checks every request with the real verifier, then gives the next scripted answer.
    struct Scripted {
        verifier: Mutex<Verifier>,
        replies: Mutex<VecDeque<Result<Incoming, LinkProblem>>>,
        seen: Mutex<Vec<Seen>>,
    }

    impl Scripted {
        fn new(replies: Vec<Result<Incoming, LinkProblem>>) -> Arc<Scripted> {
            Arc::new(Scripted {
                verifier: Mutex::new(Verifier::new(secret())),
                replies: Mutex::new(replies.into()),
                seen: Mutex::default(),
            })
        }

        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Transport for Scripted {
        fn send<'a>(&'a self, out: Outgoing<'a>) -> BoxFuture<'a, Result<Incoming, LinkProblem>> {
            let parts = Parts {
                method: out.method,
                path_and_query: out.path,
                time: out.time,
                nonce: out.nonce,
                body: out.body,
            };
            let verdict = self
                .verifier
                .lock()
                .unwrap()
                .verify(out.time, &parts, out.signature);
            self.seen.lock().unwrap().push(Seen {
                method: out.method,
                path: out.path,
                time: out.time,
                nonce: out.nonce.to_string(),
                body: out.body.to_vec(),
                cap: out.cap,
                verdict,
            });
            let reply = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("a scripted reply");
            Box::pin(async move { reply })
        }
    }

    fn ok(status: u16, body: &str) -> Result<Incoming, LinkProblem> {
        Ok(Incoming {
            status,
            body: body.as_bytes().to_vec(),
        })
    }

    fn link_with(replies: Vec<Result<Incoming, LinkProblem>>) -> (Link, Arc<Scripted>) {
        let transport = Scripted::new(replies);
        (Link::new(transport.clone(), secret()), transport)
    }

    // ---- signing ----

    #[tokio::test]
    async fn a_status_request_is_signed_so_the_agents_own_verifier_accepts_it() {
        let (link, transport) = link_with(vec![ok(200, &status_json())]);

        link.status(1_000).await.unwrap();

        let seen = transport.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!((seen[0].method, seen[0].path), ("GET", "/v1/status"));
        assert_eq!(seen[0].verdict, Ok(()));
        assert!(seen[0].body.is_empty());
        assert_eq!(seen[0].cap, STATUS_CAP);
        assert_eq!(seen[0].time, 1_000);
    }

    #[tokio::test]
    async fn a_request_signed_with_another_secret_is_refused_by_the_verifier() {
        let transport = Scripted::new(vec![ok(404, "")]);
        let link = Link::new(transport.clone(), unhex(OTHER_SECRET_HEX).unwrap());

        let _ = link.status(1_000).await;

        assert_eq!(transport.seen()[0].verdict, Err(Refusal::BadSignature));
    }

    #[tokio::test]
    async fn a_put_carries_the_list_as_json_and_signs_the_body() {
        let (link, transport) = link_with(vec![ok(
            200,
            r#"{"version":7,"added":1,"removed":0,"updated":0}"#,
        )]);

        link.put_peers(1_000, &list()).await.unwrap();

        let seen = transport.seen();
        assert_eq!((seen[0].method, seen[0].path), ("PUT", "/v1/peers"));
        assert_eq!(
            seen[0].verdict,
            Ok(()),
            "the body hash is part of the signature"
        );
        assert_eq!(seen[0].body, serde_json::to_vec(&list()).unwrap());
        assert_eq!(seen[0].cap, ANSWER_CAP);
        let sent: PeerList = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(sent, list());
    }

    #[tokio::test]
    async fn nonces_never_repeat_and_times_always_rise_even_within_one_second() {
        let (link, transport) = link_with(vec![
            ok(200, &status_json()),
            ok(200, &status_json()),
            ok(200, &status_json()),
            ok(200, &status_json()),
        ]);

        for _ in 0..3 {
            link.status(5_000).await.unwrap();
        }
        link.status(5_100).await.unwrap();

        let seen = transport.seen();
        let times: Vec<u64> = seen.iter().map(|s| s.time).collect();
        assert_eq!(times, [5_000, 5_001, 5_002, 5_100]);
        let mut nonces: Vec<&str> = seen.iter().map(|s| s.nonce.as_str()).collect();
        nonces.sort_unstable();
        nonces.dedup();
        assert_eq!(nonces.len(), 4);
        assert!(seen.iter().all(|s| s.verdict == Ok(())));
        assert!(seen.iter().all(|s| s.nonce.len() == 32));
    }

    #[tokio::test]
    async fn a_replacement_link_carries_on_after_the_times_of_the_one_it_replaces() {
        let (old, _) = link_with(vec![ok(200, &status_json())]);
        old.status(7_000).await.unwrap();
        assert_eq!(old.last_time(), 7_000);
        let transport = Scripted::new(vec![ok(200, &status_json())]);
        let new = Link::new(transport.clone(), secret()).starting_after(old.last_time());

        new.status(7_000).await.unwrap();

        assert_eq!(transport.seen()[0].time, 7_001);
    }

    #[tokio::test]
    async fn a_clock_that_steps_back_still_gives_a_later_time() {
        let (link, transport) = link_with(vec![ok(200, &status_json()), ok(200, &status_json())]);

        link.status(9_000).await.unwrap();
        link.status(8_990).await.unwrap();

        let times: Vec<u64> = transport.seen().iter().map(|s| s.time).collect();
        assert_eq!(times, [9_000, 9_001]);
    }

    // ---- reading the status ----

    #[tokio::test]
    async fn the_status_an_agent_really_produces_is_read_and_the_client_address_is_dropped() {
        let (link, _) = link_with(vec![ok(200, &status_json())]);

        let reading = link.status(1_000).await.unwrap();

        assert_eq!(reading.wg_public_key, NODE_KEY);
        assert_eq!(reading.listen_port, 51820);
        assert_eq!((reading.online, reading.peers_total), (1, 2));
        assert_eq!(reading.desired_version, Some(7));
        assert_eq!(reading.load1, Some(0.25));
        assert_eq!(
            reading.peers,
            vec![
                PeerReading {
                    public_key: K1.to_string(),
                    online: true,
                    handshake_age: Some(12),
                    rx: 100,
                    tx: 200
                },
                PeerReading {
                    public_key: K2.to_string(),
                    online: false,
                    handshake_age: None,
                    rx: 0,
                    tx: 0
                },
            ]
        );
        assert!(!format!("{reading:?}").contains("203.0.113"));
    }

    #[tokio::test]
    async fn a_status_without_a_list_or_a_load_reads_as_none_not_zero() {
        let body = format!(
            r#"{{"time":1,"interface":{{"public_key":"{NODE_KEY}","listen_port":1}},"online":0,"peers_total":0,"desired_version":null,"load1":null,"peers":[],"future_field":[1,2]}}"#
        );
        let (link, _) = link_with(vec![ok(200, &body)]);

        let reading = link.status(1).await.unwrap();

        assert_eq!(reading.desired_version, None);
        assert_eq!(reading.load1, None);
        assert!(reading.peers.is_empty());
    }

    #[tokio::test]
    async fn a_status_that_is_not_the_agents_shape_is_a_bad_answer() {
        for body in [
            "",
            "null",
            "[]",
            "not json",
            r#"{"time":1}"#,
            r#"{"time":1,"interface":{"public_key":"k"},"online":0,"peers_total":0,"peers":[]}"#,
            r#"{"time":1,"interface":{"public_key":"k","listen_port":1},"online":-1,"peers_total":0,"peers":[]}"#,
        ] {
            let (link, _) = link_with(vec![ok(200, body)]);
            assert_eq!(
                link.status(1).await,
                Err(LinkProblem::BadAnswer),
                "{body:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_status_with_a_key_that_is_not_a_canonical_wireguard_key_is_refused_whole() {
        let good_peer = format!(
            r#"{{"public_key":"{K1}","allowed_ips":[],"handshake_age":null,"online":false,"rx":0,"tx":0}}"#
        );
        for (what, server_key, peer_key) in [
            ("an escape sequence", r"\u001b[2J\u001b[31mowned", K1),
            ("a newline", r"AAAA\nBBBB", K1),
            ("not 32 bytes", "AAAA", K1),
            (
                "a bidi mark",
                r"\u202eAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                K1,
            ),
            ("a bad peer key", NODE_KEY, r"\u001b]0;pwned\u0007"),
            ("an empty peer key", NODE_KEY, ""),
        ] {
            let body = format!(
                r#"{{"time":1,"interface":{{"public_key":"{server_key}","listen_port":1}},"online":0,"peers_total":2,"peers":[{good_peer},{{"public_key":"{peer_key}","allowed_ips":[],"handshake_age":null,"online":false,"rx":0,"tx":0}}]}}"#
            );
            let (link, _) = link_with(vec![ok(200, &body)]);
            assert_eq!(link.status(1).await, Err(LinkProblem::BadAnswer), "{what}");
        }
    }

    #[tokio::test]
    async fn a_reason_from_the_node_loses_bidi_marks_and_zero_width_characters_too() {
        let body = r#"{"error":"bad_list","detail":"a\u202eb\u200bc\u2066d"}"#;

        let Err(LinkProblem::BadList { detail }) = put_answer(ok(400, body)).await else {
            panic!("a bad list");
        };

        assert_eq!(detail, "abcd");
    }

    // ---- reading the answers ----

    async fn status_answer(reply: Result<Incoming, LinkProblem>) -> LinkProblem {
        let (link, _) = link_with(vec![reply]);
        link.status(1).await.unwrap_err()
    }

    async fn put_answer(reply: Result<Incoming, LinkProblem>) -> Result<Pushed, LinkProblem> {
        let (link, _) = link_with(vec![reply]);
        link.put_peers(1, &list()).await
    }

    #[tokio::test]
    async fn status_answers_are_told_apart() {
        assert_eq!(status_answer(ok(404, "")).await, LinkProblem::Refused);
        assert_eq!(
            status_answer(ok(503, r#"{"error":"unavailable"}"#)).await,
            LinkProblem::Unavailable
        );
        assert_eq!(status_answer(ok(500, "")).await, LinkProblem::Server(500));
        assert_eq!(status_answer(ok(302, "")).await, LinkProblem::Server(302));
        assert_eq!(status_answer(ok(204, "")).await, LinkProblem::Server(204));
        assert_eq!(status_answer(ok(401, "")).await, LinkProblem::Server(401));
        for problem in [
            LinkProblem::Certificate,
            LinkProblem::Unreachable,
            LinkProblem::Timeout,
            LinkProblem::TooLarge,
            LinkProblem::Connection,
        ] {
            assert_eq!(status_answer(Err(problem.clone())).await, problem);
        }
    }

    #[tokio::test]
    async fn a_put_that_was_applied_says_what_it_did() {
        let pushed = put_answer(ok(
            200,
            r#"{"version":7,"added":1,"removed":2,"updated":3}"#,
        ))
        .await;

        assert_eq!(
            pushed,
            Ok(Pushed {
                version: 7,
                added: 1,
                removed: 2,
                updated: 3
            })
        );
        assert_eq!(
            put_answer(ok(200, "{}")).await,
            Err(LinkProblem::BadAnswer),
            "a 200 without the counts is not an agent's answer"
        );
        assert_eq!(put_answer(ok(200, "")).await, Err(LinkProblem::BadAnswer));
    }

    #[tokio::test]
    async fn a_put_that_was_refused_says_why() {
        assert_eq!(
            put_answer(ok(409, r#"{"error":"stale","stored_version":9}"#)).await,
            Err(LinkProblem::Stale { stored: Some(9) })
        );
        assert_eq!(
            put_answer(ok(409, "weird")).await,
            Err(LinkProblem::Stale { stored: None })
        );
        assert_eq!(
            put_answer(ok(
                400,
                r#"{"error":"bad_list","detail":"peers[3]: not a valid WireGuard key"}"#
            ))
            .await,
            Err(LinkProblem::BadList {
                detail: "peers[3]: not a valid WireGuard key".to_string()
            })
        );
        assert_eq!(
            put_answer(ok(400, r#"{"error":"bad_request"}"#)).await,
            Err(LinkProblem::BadRequest)
        );
        assert_eq!(put_answer(ok(400, "")).await, Err(LinkProblem::BadRequest));
        assert_eq!(put_answer(ok(404, "")).await, Err(LinkProblem::Refused));
        assert_eq!(
            put_answer(ok(500, r#"{"error":"store_failed"}"#)).await,
            Err(LinkProblem::Server(500))
        );
        assert_eq!(
            put_answer(ok(503, r#"{"error":"unavailable"}"#)).await,
            Err(LinkProblem::Unavailable)
        );
    }

    #[tokio::test]
    async fn a_reason_from_the_node_is_trimmed_to_plain_short_text() {
        let long = "x".repeat(500);
        let body = format!(r#"{{"error":"bad_list","detail":"a\u0007b\nc{long}"}}"#);

        let Err(LinkProblem::BadList { detail }) = put_answer(ok(400, &body)).await else {
            panic!("a bad list");
        };

        assert!(detail.starts_with("abc"), "{detail:?}");
        assert!(detail.chars().count() <= 120);
        assert!(detail.chars().all(|c| !c.is_control()));
    }

    #[test]
    fn every_problem_reads_as_a_sentence_and_none_holds_a_secret() {
        let problems = [
            LinkProblem::Certificate,
            LinkProblem::Unreachable,
            LinkProblem::Timeout,
            LinkProblem::TooLarge,
            LinkProblem::Connection,
            LinkProblem::BadAnswer,
            LinkProblem::Refused,
            LinkProblem::Unavailable,
            LinkProblem::Stale { stored: Some(4) },
            LinkProblem::Stale { stored: None },
            LinkProblem::BadList {
                detail: "peers[0]: x".into(),
            },
            LinkProblem::BadRequest,
            LinkProblem::Server(502),
        ];
        for problem in problems {
            let text = problem.to_string();
            assert!(text.len() > 10, "{problem:?}");
            assert!(!text.contains(SECRET_HEX));
        }
        assert!(LinkProblem::Server(502).to_string().contains("502"));
        assert!(
            LinkProblem::Stale { stored: Some(4) }
                .to_string()
                .contains('4')
        );
    }

    #[test]
    fn debug_output_never_shows_a_secret_or_a_root() {
        let (link, _) = link_with(vec![]);
        let files = NodeFiles {
            secret: secret(),
            root_pem: b"-----BEGIN CERTIFICATE-----".to_vec(),
        };

        for text in [format!("{link:?}"), format!("{files:?}")] {
            assert!(!text.contains("00112233"), "{text}");
            assert!(!text.contains("[0, 17"), "{text}");
            assert!(!text.contains("BEGIN"), "{text}");
        }
    }

    // ---- the files ----

    fn node_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bf-link-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_mode(path: &Path, content: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, content).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn good_root() -> String {
        Authority::root("Test Root").pem()
    }

    #[test]
    fn a_node_with_a_private_secret_and_a_root_is_read() {
        let dir = node_dir("good");
        write_mode(
            &dir.join("toronto.secret"),
            &format!("{SECRET_HEX}\n"),
            0o400,
        );
        std::fs::write(dir.join("toronto.pem"), good_root()).unwrap();

        let files = read_files(&dir, "toronto").unwrap();

        assert_eq!(files.secret(), secret().as_slice());
        assert!(files.root_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn a_missing_file_is_named_and_a_node_is_not_confused_with_another() {
        let dir = node_dir("missing");
        write_mode(&dir.join("dallas.secret"), SECRET_HEX, 0o600);
        std::fs::write(dir.join("dallas.pem"), good_root()).unwrap();

        assert_eq!(
            read_files(&dir, "toronto"),
            Err(FilesProblem::SecretMissing)
        );
        write_mode(&dir.join("toronto.secret"), SECRET_HEX, 0o600);
        assert_eq!(read_files(&dir, "toronto"), Err(FilesProblem::RootMissing));
        let Err(FilesProblem::SecretUnusable(why)) =
            read_files(&node_dir("nodir").join("nowhere"), "toronto")
        else {
            panic!("a directory that is not there");
        };
        assert!(why.contains("does not exist"), "{why}");
    }

    #[test]
    fn a_secret_that_others_can_read_or_that_is_short_or_not_hex_is_refused_without_quoting_it() {
        let dir = node_dir("badsecret");
        std::fs::write(dir.join("n.pem"), good_root()).unwrap();
        let path = dir.join("n.secret");

        for mode in [0o644, 0o640, 0o604] {
            write_mode(&path, SECRET_HEX, mode);
            let Err(FilesProblem::SecretUnusable(why)) = read_files(&dir, "n") else {
                panic!("{mode:o} must be refused");
            };
            assert!(why.contains("others"), "{why}");
            assert!(!why.contains("0011"));
        }
        write_mode(&path, "abcd", 0o600);
        assert_eq!(read_files(&dir, "n"), Err(FilesProblem::SecretTooShort));
        write_mode(&path, "", 0o600);
        assert_eq!(read_files(&dir, "n"), Err(FilesProblem::SecretTooShort));
        write_mode(&path, &"zz".repeat(32), 0o600);
        assert_eq!(read_files(&dir, "n"), Err(FilesProblem::SecretNotHex));
        write_mode(&path, &format!("{SECRET_HEX}x"), 0o600);
        assert_eq!(read_files(&dir, "n"), Err(FilesProblem::SecretNotHex));
        write_mode(&path, &"ab".repeat(100_000), 0o600);
        assert!(matches!(
            read_files(&dir, "n"),
            Err(FilesProblem::SecretUnusable(_))
        ));
    }

    #[test]
    fn a_root_that_is_not_one_or_two_pem_certificates_is_refused() {
        let dir = node_dir("badroot");
        write_mode(&dir.join("n.secret"), SECRET_HEX, 0o600);
        let path = dir.join("n.pem");

        for content in [
            String::new(),
            "hello".to_string(),
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_string(),
            format!("{}{}{}", good_root(), good_root(), good_root()),
        ] {
            std::fs::write(&path, &content).unwrap();
            assert_eq!(
                read_files(&dir, "n"),
                Err(FilesProblem::RootUnusable),
                "{content:?}"
            );
        }
        std::fs::write(&path, format!("{}{}", good_root(), good_root())).unwrap();
        assert!(read_files(&dir, "n").is_ok(), "two certificates are fine");
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(read_files(&dir, "n"), Err(FilesProblem::RootUnusable));
    }

    #[test]
    fn a_secret_of_31_bytes_is_too_short_and_32_is_enough() {
        let dir = node_dir("boundary");
        std::fs::write(dir.join("n.pem"), good_root()).unwrap();

        write_mode(&dir.join("n.secret"), &"ab".repeat(31), 0o600);
        assert_eq!(read_files(&dir, "n"), Err(FilesProblem::SecretTooShort));
        write_mode(&dir.join("n.secret"), &"ab".repeat(32), 0o600);
        assert!(read_files(&dir, "n").is_ok());
    }

    #[test]
    fn a_root_file_that_is_far_too_big_is_refused() {
        let dir = node_dir("bigroot");
        write_mode(&dir.join("n.secret"), SECRET_HEX, 0o600);
        std::fs::write(
            dir.join("n.pem"),
            format!("{}{}", good_root(), "# padding\n".repeat(10_000)),
        )
        .unwrap();

        assert_eq!(read_files(&dir, "n"), Err(FilesProblem::RootUnusable));
    }

    #[test]
    fn a_name_that_could_walk_out_of_the_directory_finds_nothing() {
        let dir = node_dir("walk");
        let inner = dir.join("nodes");
        std::fs::create_dir_all(&inner).unwrap();
        write_mode(&dir.join("evil.secret"), SECRET_HEX, 0o600);
        std::fs::write(dir.join("evil.pem"), good_root()).unwrap();

        for name in ["../evil", "..", "", "a/b", "/etc/passwd", "Evil"] {
            assert_eq!(
                read_files(&inner, name),
                Err(FilesProblem::SecretMissing),
                "{name:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_answer_of_exactly_the_cap_is_read_and_one_byte_more_is_not() {
        let head = r#"{"version":7,"added":0,"removed":0,"updated":0}"#;
        let exact = format!("{head}{}", " ".repeat(ANSWER_CAP - head.len()));
        assert_eq!(exact.len(), ANSWER_CAP);
        let (root, intermediate) = caddy_like();
        let bodies = Arc::new(Mutex::new(VecDeque::from([
            exact.clone(),
            format!("{exact} "),
        ])));
        let queue = bodies.clone();
        let handler: Handler =
            Arc::new(move |_| Response::new(200, queue.lock().unwrap().pop_front().unwrap()));
        let server = Server::tls(intermediate.leaf(&[HOST], false), handler);
        let link = real_link(&server, &root);

        assert!(link.put_peers(1, &list()).await.is_ok());
        assert_eq!(link.put_peers(2, &list()).await, Err(LinkProblem::TooLarge));
    }

    #[test]
    fn a_file_problem_never_holds_what_was_in_the_file() {
        let dir = node_dir("quiet");
        write_mode(&dir.join("n.secret"), "SECRETWORDS-not-hex", 0o600);
        std::fs::write(dir.join("n.pem"), "PRIVATE-ROOT-WORDS").unwrap();

        let secret_problem = read_files(&dir, "n").unwrap_err().to_string();
        write_mode(&dir.join("n.secret"), SECRET_HEX, 0o600);
        let root_problem = read_files(&dir, "n").unwrap_err().to_string();

        assert!(!secret_problem.contains("SECRETWORDS"));
        assert!(!root_problem.contains("ROOT-WORDS"));
    }

    // ---- the real connection ----

    const NAME: &str = "toronto";
    const HOST: &str = "toronto.agent.internal";

    /// What the handler decided about each request it saw, in order.
    type Verdicts = Arc<Mutex<Vec<Result<(), Refusal>>>>;

    /// A handler that checks the signature like the agent and answers with the status.
    fn agent_handler(secret: Vec<u8>, body: String) -> (Handler, Verdicts) {
        let verdicts: Verdicts = Arc::default();
        let seen = verdicts.clone();
        let verifier = Mutex::new(Verifier::new(secret));
        let handler: Handler = Arc::new(move |request| {
            let time = request
                .header("x-bf-time")
                .and_then(|t| t.parse().ok())
                .unwrap_or(0);
            let nonce = request.header("x-bf-nonce").unwrap_or("").to_string();
            let signature = request.header("x-bf-sig").unwrap_or("").to_string();
            let verdict = verifier.lock().unwrap().verify(
                time,
                &Parts {
                    method: &request.method,
                    path_and_query: &request.path,
                    time,
                    nonce: &nonce,
                    body: &request.body,
                },
                &signature,
            );
            seen.lock().unwrap().push(verdict);
            match verdict {
                Ok(()) => Response::new(200, body.clone()),
                Err(_) => Response::new(404, ""),
            }
        });
        (handler, verdicts)
    }

    fn real_link(server: &Server, root: &Authority) -> Link {
        let transport = HttpsTransport::new(NAME, server.addr, root.pem().as_bytes()).unwrap();
        Link::new(Arc::new(transport), secret())
    }

    /// Roots like Caddy's: a root that signs an intermediate that signs the leaf.
    fn caddy_like() -> (Authority, Authority) {
        let root = Authority::root("Barely-free Test Root");
        let intermediate = root.intermediate("Barely-free Test Intermediate");
        (root, intermediate)
    }

    #[tokio::test]
    async fn a_node_with_a_leaf_from_the_pinned_root_for_its_name_is_reached_and_asked_by_name() {
        let (root, intermediate) = caddy_like();
        let (handler, verdicts) = agent_handler(secret(), status_json());
        let server = Server::tls(intermediate.leaf(&[HOST], false), handler);

        let reading = real_link(&server, &root).status(1_000).await.unwrap();

        assert_eq!(reading.desired_version, Some(7));
        assert_eq!(
            *verdicts.lock().unwrap(),
            vec![Ok(())],
            "signed and accepted"
        );
        assert_eq!(server.requests(), 1);
    }

    #[tokio::test]
    async fn the_node_is_asked_for_by_its_name_even_though_we_connect_to_its_address() {
        let (root, intermediate) = caddy_like();
        let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
        let log = seen.clone();
        let handler: Handler = Arc::new(move |request| {
            log.lock().unwrap().push(request.sni.clone());
            log.lock()
                .unwrap()
                .push(request.header("host").map(str::to_string));
            Response::new(404, "")
        });
        let server = Server::tls(intermediate.leaf(&[HOST], false), handler);

        let _ = real_link(&server, &root).status(1_000).await;

        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].as_deref(), Some(HOST), "the SNI");
        assert!(
            seen[1].as_deref().unwrap().starts_with(HOST),
            "the Host header"
        );
    }

    #[tokio::test]
    async fn a_leaf_from_another_authority_is_refused_before_any_request_is_sent() {
        let (root, _) = caddy_like();
        let (other_root, other_intermediate) = caddy_like();
        let (handler, _) = agent_handler(secret(), status_json());
        let server = Server::tls(other_intermediate.leaf(&[HOST], false), handler);

        let result = real_link(&server, &root).status(1_000).await;

        assert_eq!(result, Err(LinkProblem::Certificate));
        assert_eq!(server.requests(), 0, "nothing signed ever reached it");
        let _ = other_root;
    }

    #[tokio::test]
    async fn a_leaf_for_another_name_an_expired_one_and_a_self_signed_one_are_all_refused() {
        let (root, intermediate) = caddy_like();
        let leaves = [
            (
                "another name",
                intermediate.leaf(&["dallas.agent.internal"], false),
            ),
            ("expired", intermediate.leaf(&[HOST], true)),
            ("self-signed", self_signed_leaf(&[HOST])),
            ("a plain address", intermediate.leaf(&["127.0.0.1"], false)),
        ];
        for (what, leaf) in leaves {
            let (handler, _) = agent_handler(secret(), status_json());
            let server = Server::tls(leaf, handler);

            let result = real_link(&server, &root).status(1_000).await;

            assert_eq!(result, Err(LinkProblem::Certificate), "{what}");
            assert_eq!(server.requests(), 0, "{what}");
        }
    }

    #[tokio::test]
    async fn the_same_root_does_not_vouch_for_a_different_node_name() {
        let (root, intermediate) = caddy_like();
        let (handler, _) = agent_handler(secret(), status_json());
        let server = Server::tls(intermediate.leaf(&[HOST], false), handler);
        // Same authority, same server, but the link is configured for another node.
        let transport = HttpsTransport::new("dallas", server.addr, root.pem().as_bytes()).unwrap();
        let link = Link::new(Arc::new(transport), secret());

        assert_eq!(link.status(1_000).await, Err(LinkProblem::Certificate));
    }

    #[tokio::test]
    async fn a_server_that_speaks_plain_http_is_never_talked_to_in_the_clear() {
        let (root, _) = caddy_like();
        let (handler, verdicts) = agent_handler(secret(), status_json());
        let server = Server::plain(handler);

        let result = real_link(&server, &root).status(1_000).await;

        assert!(result.is_err());
        assert!(
            verdicts.lock().unwrap().is_empty(),
            "no signed request was readable"
        );
    }

    #[tokio::test]
    async fn nothing_listening_is_unreachable() {
        let (root, _) = caddy_like();
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let transport = HttpsTransport::new(NAME, closed, root.pem().as_bytes()).unwrap();

        let result = Link::new(Arc::new(transport), secret()).status(1).await;

        assert_eq!(result, Err(LinkProblem::Unreachable));
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let (root, intermediate) = caddy_like();
        let (target_handler, _) = agent_handler(secret(), status_json());
        let target = Server::plain(target_handler);
        let location = format!("http://{}/v1/status", target.addr);
        let handler: Handler = Arc::new(move |_| {
            let mut redirect = Response::new(302, "");
            redirect
                .headers
                .push(("Location".to_string(), location.clone()));
            redirect
        });
        let server = Server::tls(intermediate.leaf(&[HOST], false), handler);

        let result = real_link(&server, &root).status(1_000).await;

        assert_eq!(result, Err(LinkProblem::Server(302)));
        assert_eq!(target.requests(), 0);
    }

    #[tokio::test]
    async fn a_node_that_never_answers_ends_at_the_deadline() {
        let (root, intermediate) = caddy_like();
        let handler: Handler = Arc::new(|_| {
            std::thread::sleep(Duration::from_secs(3));
            Response::new(200, "")
        });
        let server = Server::tls(intermediate.leaf(&[HOST], false), handler);
        let transport = HttpsTransport::with_timeouts(
            NAME,
            server.addr,
            root.pem().as_bytes(),
            Timeouts {
                connect: Duration::from_millis(500),
                total: Duration::from_millis(400),
            },
        )
        .unwrap();
        let started = std::time::Instant::now();

        let result = Link::new(Arc::new(transport), secret()).status(1).await;

        assert_eq!(result, Err(LinkProblem::Timeout));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn an_answer_over_the_cap_is_refused_whether_or_not_it_says_how_long_it_is() {
        let (root, intermediate) = caddy_like();
        let count = Arc::new(AtomicUsize::new(0));
        let n = count.clone();
        let handler: Handler = Arc::new(move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            Response::new(200, vec![b' '; STATUS_CAP + 1])
        });
        let server = Server::tls(intermediate.leaf(&[HOST], false), handler);

        let result = real_link(&server, &root).status(1).await;

        assert_eq!(result, Err(LinkProblem::TooLarge));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_answer_that_does_not_say_its_length_is_cut_off_at_the_cap_too() {
        let (root, intermediate) = caddy_like();
        let handler: Handler = Arc::new(|_| {
            let mut big = Response::new(200, vec![b' '; ANSWER_CAP + 1]);
            big.headers
                .push(("Transfer-Encoding".to_string(), "chunked".to_string()));
            big
        });
        let server = Server::tls(intermediate.leaf(&[HOST], false), handler);

        let result = real_link(&server, &root).put_peers(1, &list()).await;

        assert_eq!(result, Err(LinkProblem::TooLarge));
    }

    #[tokio::test]
    async fn a_small_answer_is_not_confused_with_a_big_one_and_a_put_over_tls_works() {
        let (root, intermediate) = caddy_like();
        let (handler, verdicts) = agent_handler(
            secret(),
            r#"{"version":7,"added":1,"removed":0,"updated":0}"#.to_string(),
        );
        let server = Server::tls(intermediate.leaf(&[HOST], false), handler);

        let pushed = real_link(&server, &root)
            .put_peers(1_000, &list())
            .await
            .unwrap();

        assert_eq!(pushed.version, 7);
        assert_eq!(
            *verdicts.lock().unwrap(),
            vec![Ok(())],
            "the body was signed"
        );
    }

    /// Manual check against the two real nodes, with no secret: the pinned client must finish a
    /// TLS handshake with Caddy's real certificate chain for `<node>.agent.internal`, and the
    /// agent must answer a request signed with a made-up secret with its plain 404, which the
    /// link reports as "refused". Run it with
    /// `cargo test -p bf-control --lib real_nodes -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "talks to the real nodes over the internet"]
    async fn real_nodes_accept_the_pinned_root_and_refuse_a_made_up_secret() {
        let nodes = [
            ("toronto", "192.0.2.176:8443"),
            ("dallas", "198.51.100.185:8443"),
        ];
        for (name, address) in nodes {
            let root = std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("../../deploy/node-roots/{name}.pem")),
            )
            .unwrap();
            let transport = HttpsTransport::new(name, address.parse().unwrap(), &root).unwrap();
            let link = Link::new(Arc::new(transport), vec![7u8; 32]);

            let result = link
                .status(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                )
                .await;

            println!("{name}: {result:?}");
            assert_eq!(result, Err(LinkProblem::Refused), "{name}");
        }

        // The pin is per node: Dallas's root does not vouch for Toronto's address.
        let dallas_root = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/node-roots/dallas.pem"),
        )
        .unwrap();
        let wrong =
            HttpsTransport::new("toronto", nodes[0].1.parse().unwrap(), &dallas_root).unwrap();
        let result = Link::new(Arc::new(wrong), vec![7u8; 32])
            .status(1_700_000_000)
            .await;
        println!("toronto with dallas's root: {result:?}");
        assert_eq!(result, Err(LinkProblem::Certificate));
    }

    #[test]
    fn a_transport_cannot_be_built_from_a_root_that_is_not_pem() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        for bad in [
            &b""[..],
            b"hello",
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ] {
            assert!(matches!(
                HttpsTransport::new(NAME, addr, bad),
                Err(FilesProblem::RootUnusable)
            ));
        }
    }
}

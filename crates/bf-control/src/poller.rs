//! The poller: keeps every node's WireGuard in step with the database, and knows which
//! nodes are alive (`specs/poller.md`).
//!
//! Once per pass it publishes the peer list (one list for all nodes), then, for each
//! enabled node at the same time, asks for its status and sends the list if the node does
//! not hold the current version. What it learns goes on a [`Board`] in memory; nothing
//! about the nodes' peers is written to disk.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bf_common::peers::PeerList;
use tokio::sync::Notify;
use tokio::task::JoinSet;

use crate::link::{
    FilesProblem, HttpsTransport, Link, LinkProblem, NodeFiles, NodeReading, read_files_unchecked,
};
use crate::nodes::Node;
use crate::protocol::{self, Protocol};
use crate::store::{Store, StoreError};

/// A reading older than this is shown as unknown, at the least. With a longer interval it is
/// two intervals and a node's deadline (see [`Settings::stale_after`]).
pub const STALE_AFTER_SECS: u64 = 60;

/// `BC_POLL_SECS`: a whole number from 2 to 300, 10 if not set.
pub fn poll_interval(setting: Option<&str>) -> Result<Duration, &'static str> {
    const WHY: &str = "BC_POLL_SECS must be a whole number of seconds from 2 to 300";
    let Some(text) = setting else {
        return Ok(Duration::from_secs(10));
    };
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WHY);
    }
    match text.parse::<u64>() {
        Ok(secs) if (2..=300).contains(&secs) => Ok(Duration::from_secs(secs)),
        _ => Err(WHY),
    }
}

/// How a node looks to the public.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Health {
    /// No reading yet, or none recent enough.
    #[default]
    Unknown,
    Online,
    /// Three passes in a row failed.
    NotResponding,
    /// The node is disabled (`node disable`): switched off on purpose, not visited.
    BeingFixed,
}

impl Health {
    /// The words the public page uses.
    pub fn label(self) -> &'static str {
        match self {
            Health::Unknown => "Status unknown",
            Health::Online => "Online",
            Health::NotResponding => "Not responding",
            Health::BeingFixed => "Being fixed",
        }
    }
}

/// What is wrong with a node, in a form the admin can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// Its secret or root file cannot be used.
    Files(FilesProblem),
    /// A call failed.
    Link(LinkProblem),
    /// The node holds a newer list than the database (a restored backup).
    Ahead { node: u64, database: u64 },
    /// The poller itself failed on this node.
    Internal,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::Files(p) => write!(f, "{p}"),
            Problem::Link(p) => write!(f, "{p}"),
            Problem::Ahead { node, database } => write!(
                f,
                "ahead of the database (node {node}, database {database}); raise the database's version"
            ),
            Problem::Internal => f.write_str("the poller failed on this node"),
        }
    }
}

/// What the poller knows about one node.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeView {
    pub name: String,
    pub title: String,
    pub place: String,
    /// What the node's agent speaks (`None`: registered before protocols, not offered for
    /// new devices).
    pub protocol: Option<Protocol>,
    /// Where its server is, if set (`node set-location`), for "Closest to you".
    pub location: Option<crate::closest::Location>,
    /// The node's address: where a device's WireGuard endpoint is (the port is the one the
    /// node's WireGuard listens on, from its status).
    pub ip: std::net::IpAddr,
    pub health: Health,
    /// When the last pass for this node finished.
    pub checked_at: u64,
    /// The last time the node answered a status request.
    pub last_good: Option<u64>,
    /// The reading from the last pass, only if that pass worked. A pass that failed has
    /// none: there is no count of 0, just no count.
    pub reading: Option<NodeReading>,
    pub problem: Option<Problem>,
    /// Whether the node holds the list the database published in the last pass.
    pub in_sync: bool,
}

/// The poller's findings, shared with the website.
pub struct Board {
    inner: Mutex<BoardInner>,
    /// Seconds after the end of a pass at which what it found reads as unknown.
    stale_after: std::sync::atomic::AtomicU64,
}

impl Default for Board {
    fn default() -> Self {
        Board {
            inner: Mutex::default(),
            stale_after: std::sync::atomic::AtomicU64::new(STALE_AFTER_SECS),
        }
    }
}

#[derive(Default)]
struct BoardInner {
    views: Vec<NodeView>,
    list_version: Option<u64>,
    updated_at: Option<u64>,
    contacts: BTreeMap<String, Contact>,
    /// The remembered devices the last informative poll did not list (see [`remembered`]).
    missing: std::collections::BTreeSet<String>,
}

/// The newest handshake the website has read for one device: when, and through which
/// server. The servers forget a device 5 minutes after its last handshake
/// (`bf_common::wg::FORGET_IDLE_AFTER_SECS`), so the account page's "last connected" comes
/// from here. Kept in memory only, by public key, with no address; gone when the website
/// restarts or no server lists the device any more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// Unix seconds of the handshake.
    pub at: u64,
    pub server: String,
    pub protocol: Option<Protocol>,
}

/// The board at one moment.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub nodes: Vec<NodeView>,
    /// The version of the list published in the last pass.
    pub list_version: Option<u64>,
    /// When the last pass finished; `None` before the first.
    pub updated_at: Option<u64>,
    /// The newest contact remembered for each device, by public key ([`Contact`]).
    pub contacts: BTreeMap<String, Contact>,
}

impl Board {
    pub fn new() -> Arc<Board> {
        Arc::new(Board::default())
    }

    /// How old a reading may be before it reads as unknown (at least [`STALE_AFTER_SECS`]).
    pub fn set_stale_after(&self, secs: u64) {
        self.stale_after.store(
            secs.max(STALE_AFTER_SECS),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Like [`Board::snapshot`] without the per-device readings, for the public page: it asks
    /// for nothing but the names and the health, so a request does not copy every peer.
    pub fn snapshot_light(&self, now: u64) -> Snapshot {
        let mut snapshot = self.snapshot_with(now, false);
        for node in &mut snapshot.nodes {
            node.reading = None;
            node.problem = None;
        }
        snapshot
    }

    /// Like [`Board::snapshot_light`], but each reading keeps how many devices are online and
    /// the load, which is all the status page needs to call a server overloaded. No device,
    /// no handshake, no byte count, no login and no problem text is kept, and no remembered
    /// contact.
    pub fn snapshot_counts(&self, now: u64) -> Snapshot {
        let mut snapshot = self.snapshot_with(now, false);
        for node in &mut snapshot.nodes {
            node.problem = None;
            if let Some(reading) = &mut node.reading {
                reading.peers = Vec::new();
                reading.logins = None;
            }
        }
        snapshot
    }

    /// Puts these views on the board as if a pass had just finished at `now`.
    #[cfg(test)]
    pub(crate) fn set_for_test(&self, views: Vec<NodeView>, now: u64) {
        self.replace(views, 1, now);
    }

    fn replace(&self, views: Vec<NodeView>, list_version: u64, now: u64) {
        let heard = heard(&views);
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut missing = std::mem::take(&mut inner.missing);
        let contacts = remembered(std::mem::take(&mut inner.contacts), &mut missing, heard);
        *inner = BoardInner {
            views,
            list_version: Some(list_version),
            updated_at: Some(now),
            contacts,
            missing,
        };
    }

    /// What the board says at `now`. If the last pass finished more than
    /// [`STALE_AFTER_SECS`] ago (the poller has stopped), every node reads as unknown and
    /// no reading is kept.
    pub fn snapshot(&self, now: u64) -> Snapshot {
        self.snapshot_with(now, true)
    }

    /// [`Board::snapshot`], with the remembered contacts only if `contacts`.
    fn snapshot_with(&self, now: u64, contacts: bool) -> Snapshot {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let stale = inner.updated_at.is_some_and(|at| {
            now.saturating_sub(at) > self.stale_after.load(std::sync::atomic::Ordering::Relaxed)
        });
        let nodes = inner
            .views
            .iter()
            .cloned()
            .map(|mut view| {
                if stale {
                    view.health = Health::Unknown;
                    view.reading = None;
                }
                view
            })
            .collect();
        Snapshot {
            nodes,
            list_version: inner.list_version,
            updated_at: inner.updated_at,
            contacts: if contacts {
                inner.contacts.clone()
            } else {
                BTreeMap::new()
            },
        }
    }
}

/// What a pass's `views` say about contacts, worked out before the board's lock is taken:
/// the handshake each device was last read with, and, if any server that holds the current
/// list answered with devices on its interface, the devices those servers list. An agent
/// that does not hold the list, or whose interface is empty (a rebooted host it has not
/// filled yet), says nothing about who is gone.
struct Heard {
    contacts: Vec<(String, Contact)>,
    listed: Option<std::collections::HashSet<String>>,
}

fn heard(views: &[NodeView]) -> Heard {
    let mut contacts = Vec::new();
    let mut listed: Option<std::collections::HashSet<String>> = None;
    for view in views {
        let Some(reading) = &view.reading else {
            continue;
        };
        for peer in &reading.peers {
            if let Some(age) = peer.handshake_age {
                contacts.push((
                    peer.public_key.clone(),
                    Contact {
                        at: view.checked_at.saturating_sub(age),
                        server: view.title.clone(),
                        protocol: view.protocol,
                    },
                ));
            }
        }
        if view.in_sync && !reading.peers.is_empty() {
            listed
                .get_or_insert_with(Default::default)
                .extend(reading.peers.iter().map(|peer| peer.public_key.clone()));
        }
    }
    Heard { contacts, listed }
}

/// `contacts` brought up to date with what a pass `heard`: each handshake replaces an older
/// one for its device. A device that the servers holding the list stop listing (removed, or
/// its account deleted) is let go once two informative polls in a row have not listed it;
/// `missing` holds the ones the last such poll did not list.
fn remembered(
    mut contacts: BTreeMap<String, Contact>,
    missing: &mut std::collections::BTreeSet<String>,
    heard: Heard,
) -> BTreeMap<String, Contact> {
    for (key, contact) in heard.contacts {
        if contacts.get(&key).is_none_or(|old| contact.at > old.at) {
            contacts.insert(key, contact);
        }
    }
    if let Some(listed) = heard.listed {
        let mut still_missing = std::collections::BTreeSet::new();
        contacts.retain(|key, _| {
            if listed.contains(key) {
                true
            } else if missing.contains(key) {
                false
            } else {
                still_missing.insert(key.clone());
                true
            }
        });
        *missing = still_missing;
    }
    contacts
}

/// How the poller makes a link to a node from its two files. The real one is
/// [`HttpsConnector`]; tests put the real agent behind a fake.
pub trait Connector: Send + Sync {
    fn connect(&self, node: &Node, files: &NodeFiles) -> Result<Link, FilesProblem>;
}

/// The pinned HTTPS connection of `link.rs`.
pub struct HttpsConnector;

impl Connector for HttpsConnector {
    fn connect(&self, node: &Node, files: &NodeFiles) -> Result<Link, FilesProblem> {
        let transport = HttpsTransport::new(&node.name, node.address, files.root_pem())?;
        Ok(Link::new(Arc::new(transport), files.secret().to_vec()))
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    /// Where `<name>.secret` and `<name>.pem` are.
    pub nodes_dir: PathBuf,
    /// Time between the end of one pass and the start of the next.
    pub every: Duration,
    /// The least time between two passes, even when poked.
    pub min_gap: Duration,
    /// One node's pass may take this long, whatever the node does.
    pub node_deadline: Duration,
    /// Failed passes in a row before a node reads "Not responding".
    pub failures_before_down: u32,
}

impl Settings {
    /// How old a reading may get before the site calls it unknown: a whole cycle (a pass of at
    /// most one node deadline, then the wait) twice over, and never under a minute.
    pub fn stale_after(&self) -> u64 {
        (2 * (self.every + self.node_deadline).as_secs()).max(STALE_AFTER_SECS)
    }

    pub fn new(nodes_dir: PathBuf, every: Duration) -> Settings {
        Settings {
            nodes_dir,
            every,
            min_gap: Duration::from_secs(1),
            node_deadline: Duration::from_secs(20),
            failures_before_down: 3,
        }
    }
}

/// What the poller remembers about a node between passes.
#[derive(Clone, Default)]
struct Slot {
    cache: Option<Cached>,
    failures: u32,
    health: Health,
    last_good: Option<u64>,
    /// What was last written to the log for this node, so a quiet pass writes nothing.
    logged: Option<String>,
}

#[derive(Clone)]
struct Cached {
    address: std::net::SocketAddr,
    files: NodeFiles,
    link: Arc<Link>,
}

pub struct Poller {
    store: Arc<Mutex<Store>>,
    settings: Settings,
    connector: Arc<dyn Connector>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    board: Arc<Board>,
    poke: Notify,
    slots: Mutex<HashMap<String, Slot>>,
    last_note: Mutex<Option<String>>,
}

impl Poller {
    pub fn new(
        store: Arc<Mutex<Store>>,
        settings: Settings,
        connector: Arc<dyn Connector>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Arc<Poller> {
        let board = Board::new();
        board.set_stale_after(settings.stale_after());
        Arc::new(Poller {
            store,
            settings,
            connector,
            clock,
            log,
            board,
            poke: Notify::new(),
            slots: Mutex::default(),
            last_note: Mutex::default(),
        })
    }

    pub fn board(&self) -> Arc<Board> {
        self.board.clone()
    }

    /// Asks for a pass now (after the minimum gap). The account page will call this right
    /// after it creates a device, so the node has the key before the person scans a code.
    pub fn poke(&self) {
        self.poke.notify_one();
    }

    /// One pass over every enabled node. A disabled node is not visited, but it stays on the
    /// board as [`Health::BeingFixed`], so the public pages can say it is switched off.
    pub async fn pass(self: &Arc<Self>) {
        let now = (self.clock)();
        let store = self.store.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            let mut store = store.lock().unwrap_or_else(PoisonError::into_inner);
            let nodes = store.nodes()?;
            let list = store.publish(now)?;
            Ok::<_, StoreError>((nodes, list))
        })
        .await;
        let (nodes, list) = match loaded {
            Ok(Ok(loaded)) => loaded,
            Ok(Err(e)) => {
                self.note(Some(format!("cannot read the nodes and the list: {e}")));
                return;
            }
            Err(_) => {
                self.note(Some("the database task failed".to_string()));
                return;
            }
        };
        self.note(None);
        // The same list for every agent, except that a WireGuard agent gets it in its own
        // range (`protocol::list_for`); the version is the same, so being in step means the
        // same thing for both.
        let wireguard = Arc::new(protocol::list_for(Some(Protocol::WireGuard), &list));
        let list = Arc::new(list);

        let mut running = JoinSet::new();
        for node in nodes.iter().filter(|node| node.enabled) {
            let previous = self.slot(&node.name);
            let list = if node.protocol == Some(Protocol::WireGuard) {
                wireguard.clone()
            } else {
                list.clone()
            };
            let (me, node) = (self.clone(), node.clone());
            running.spawn(async move {
                let fallback = previous.clone();
                let deadline = me.settings.node_deadline;
                let done =
                    tokio::time::timeout(deadline, me.visit(&node, previous, &list, now)).await;
                let (slot, view) = match done {
                    Ok(done) => done,
                    Err(_) => me.failed(&node, fallback, Problem::Link(LinkProblem::Timeout)),
                };
                (node.name.clone(), slot, view)
            });
        }
        let mut done: HashMap<String, (Slot, NodeView)> = HashMap::new();
        while let Some(joined) = running.join_next().await {
            if let Ok((name, slot, view)) = joined {
                done.insert(name, (slot, view));
            }
        }

        let mut views = Vec::with_capacity(nodes.len());
        let mut slots = HashMap::new();
        for node in &nodes {
            if !node.enabled {
                views.push(self.switched_off(node));
                continue;
            }
            // A task that panicked is a failed pass for its node, with the old state.
            let (slot, view) = done
                .remove(&node.name)
                .unwrap_or_else(|| self.failed(node, self.slot(&node.name), Problem::Internal));
            slots.insert(node.name.clone(), slot);
            views.push(view);
        }
        // Slots of nodes that were removed or disabled are dropped with this.
        *self.slots.lock().unwrap_or_else(PoisonError::into_inner) = slots;
        self.board.replace(views, list.version, (self.clock)());
    }

    /// What the board holds for a disabled node: its name and place, nothing read, nothing
    /// wrong. It is not a fault, so it has no problem, and nothing is logged for it.
    fn switched_off(&self, node: &Node) -> NodeView {
        NodeView {
            name: node.name.clone(),
            title: node.title.clone(),
            place: node.place.clone(),
            protocol: node.protocol,
            location: node.location,
            ip: node.address.ip(),
            health: Health::BeingFixed,
            checked_at: (self.clock)(),
            last_good: None,
            reading: None,
            problem: None,
            in_sync: false,
        }
    }

    fn slot(&self, name: &str) -> Slot {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    /// Writes `message` to the log unless it is what was written last (`None` clears it).
    fn note(&self, message: Option<String>) {
        let mut last = self
            .last_note
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *last != message {
            if let Some(text) = &message {
                (self.log)(text);
            } else {
                (self.log)("the database is readable again");
            }
            *last = message;
        }
    }

    /// One node's pass: its files, its status, and, if it needs it, the list.
    async fn visit(
        &self,
        node: &Node,
        mut slot: Slot,
        list: &PeerList,
        now: u64,
    ) -> (Slot, NodeView) {
        let files = match read_files_unchecked(&self.settings.nodes_dir, &node.name) {
            Ok(files) => files,
            Err(p) => return self.failed(node, slot, Problem::Files(p)),
        };
        let link = match &slot.cache {
            Some(cached) if cached.address == node.address && cached.files == files => {
                cached.link.clone()
            }
            old => {
                // Only files that are new to us are worth the cost of building a client.
                if let Err(p) = files.check_root() {
                    return self.failed(node, slot, Problem::Files(p));
                }
                let after = old.as_ref().map_or(0, |cached| cached.link.last_time());
                match self.connector.connect(node, &files) {
                    Ok(link) => {
                        let link = Arc::new(link.starting_after(after));
                        slot.cache = Some(Cached {
                            address: node.address,
                            files,
                            link: link.clone(),
                        });
                        link
                    }
                    Err(p) => return self.failed(node, slot, Problem::Files(p)),
                }
            }
        };
        let mut reading = match link.status(now).await {
            Ok(reading) => reading,
            Err(p) => return self.failed(node, slot, Problem::Link(p)),
        };
        let mut problem = None;
        // The same version is not enough: the node may hold the list on disk and not have
        // applied it (its `wg set` failed), or hold another list under that number. Its status
        // carries every peer key, so compare them. Sending the same list again is harmless
        // (the agent takes an exact retry) and makes it apply the list now.
        let same_peers = {
            let mut on_node: Vec<&str> = reading
                .peers
                .iter()
                .map(|p| p.public_key.as_str())
                .collect();
            let mut wanted: Vec<&str> = list.peers.iter().map(|p| p.public_key.as_str()).collect();
            on_node.sort_unstable();
            wanted.sort_unstable();
            on_node == wanted
        };
        match reading.desired_version {
            Some(held) if held > list.version => {
                problem = Some(Problem::Ahead {
                    node: held,
                    database: list.version,
                });
            }
            Some(held) if held == list.version && same_peers => {}
            _ => match link.put_peers(now, list).await {
                Ok(pushed) => {
                    (self.log)(&format!(
                        "node {}: list version {} sent (+{} -{} ~{})",
                        node.name, pushed.version, pushed.added, pushed.removed, pushed.updated
                    ));
                    reading.desired_version = Some(list.version);
                }
                Err(p) => problem = Some(Problem::Link(p)),
            },
        }
        slot.failures = 0;
        slot.health = Health::Online;
        slot.last_good = Some(now);
        let in_sync = problem.is_none() && reading.desired_version == Some(list.version);
        let view = NodeView {
            name: node.name.clone(),
            title: node.title.clone(),
            place: node.place.clone(),
            protocol: node.protocol,
            location: node.location,
            ip: node.address.ip(),
            health: Health::Online,
            checked_at: (self.clock)(),
            last_good: Some(now),
            reading: Some(reading),
            problem,
            in_sync,
        };
        self.log_change(node, &mut slot, &view, false);
        (slot, view)
    }

    /// A pass that did not get a status: one more failure, and no reading.
    fn failed(&self, node: &Node, mut slot: Slot, problem: Problem) -> (Slot, NodeView) {
        slot.failures = slot.failures.saturating_add(1);
        if slot.failures >= self.settings.failures_before_down {
            slot.health = Health::NotResponding;
        }
        let view = NodeView {
            name: node.name.clone(),
            title: node.title.clone(),
            place: node.place.clone(),
            protocol: node.protocol,
            location: node.location,
            ip: node.address.ip(),
            health: slot.health,
            checked_at: (self.clock)(),
            last_good: slot.last_good,
            reading: None,
            problem: Some(problem),
            in_sync: false,
        };
        self.log_change(node, &mut slot, &view, true);
        (slot, view)
    }

    /// Writes a line when what a node looks like has changed since the last line. A node
    /// that is up and misses a pass or two is not news; one that has never been seen is.
    fn log_change(&self, node: &Node, slot: &mut Slot, view: &NodeView, failed: bool) {
        if failed && view.health == Health::Online {
            return;
        }
        let message = match (&view.health, &view.problem) {
            (Health::Online, None) => "online".to_string(),
            (Health::Online, Some(p)) => format!("online, but {p}"),
            (Health::NotResponding, Some(p)) => format!("not responding: {p}"),
            (Health::Unknown, Some(p)) => format!("not answering yet: {p}"),
            (Health::BeingFixed, _) => "being fixed (disabled)".to_string(),
            (health, None) => health.label().to_lowercase(),
        };
        if slot.logged.as_deref() != Some(message.as_str()) {
            (self.log)(&format!("node {}: {message}", node.name));
            slot.logged = Some(message);
        }
    }

    /// Passes forever: one, then wait for the interval or a poke.
    pub async fn run(self: Arc<Self>) {
        loop {
            self.pass().await;
            tokio::time::sleep(self.settings.min_gap).await;
            let rest = self.settings.every.saturating_sub(self.settings.min_gap);
            tokio::select! {
                () = tokio::time::sleep(rest) => {}
                () = self.poke.notified() => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use crate::keys::KeyPair;
    use crate::store::KickEnd;
    use crate::testagent::{FakeConnector, FakeNode, T0, secret_hex};
    use crate::testtls::Authority;

    struct Rig {
        poller: Arc<Poller>,
        store: Arc<Mutex<Store>>,
        clock: Arc<AtomicU64>,
        connector: Arc<FakeConnector>,
        dir: PathBuf,
        logs: Arc<Mutex<Vec<String>>>,
        account: i64,
        next_address: std::cell::Cell<u8>,
    }

    fn rig_with(deadline: Duration) -> Rig {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bf-poller-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1).unwrap().id;
        store
            .conn
            .execute("UPDATE accounts SET device_limit = 1000", [])
            .unwrap();
        let store = Arc::new(Mutex::new(store));
        let clock = Arc::new(AtomicU64::new(T0));
        let logs: Arc<Mutex<Vec<String>>> = Arc::default();
        let connector = Arc::new(FakeConnector::default());
        let mut settings = Settings::new(dir.clone(), Duration::from_secs(10));
        settings.min_gap = Duration::from_millis(10);
        settings.node_deadline = deadline;
        let (read_clock, sink) = (clock.clone(), logs.clone());
        let poller = Poller::new(
            store.clone(),
            settings,
            connector.clone(),
            Arc::new(move || read_clock.load(Ordering::SeqCst)),
            Arc::new(move |line| sink.lock().unwrap().push(line.to_string())),
        );
        Rig {
            poller,
            store,
            clock,
            connector,
            dir,
            logs,
            account,
            next_address: std::cell::Cell::new(1),
        }
    }

    fn rig() -> Rig {
        rig_with(Duration::from_millis(500))
    }

    impl Rig {
        /// Registers a node, writes its two files, and puts a fake agent behind it.
        fn node(&self, name: &str, secret_byte: u8) -> Arc<FakeNode> {
            self.agent(name, secret_byte, None)
        }

        /// A node whose agent speaks `protocol` (`None`: registered before protocols).
        fn agent(&self, name: &str, secret_byte: u8, protocol: Option<Protocol>) -> Arc<FakeNode> {
            let n = self.next_address.get();
            self.next_address.set(n + 1);
            self.store
                .lock()
                .unwrap()
                .add_node_with(
                    name,
                    &format!("192.0.2.{n}:8443"),
                    &name.to_uppercase(),
                    "Somewhere",
                    protocol,
                    1,
                )
                .unwrap();
            self.write_files(name, secret_byte);
            let fake = FakeNode::new(self.clock.clone(), secret_byte, None);
            self.connector
                .nodes
                .lock()
                .unwrap()
                .insert(name.to_string(), fake.clone());
            fake
        }

        fn write_files(&self, name: &str, secret_byte: u8) {
            use std::os::unix::fs::PermissionsExt;
            let secret = self.dir.join(format!("{name}.secret"));
            std::fs::write(&secret, secret_hex(secret_byte)).unwrap();
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(
                self.dir.join(format!("{name}.pem")),
                Authority::root("Poller Test Root").pem(),
            )
            .unwrap();
        }

        fn add_device(&self) -> String {
            let key = KeyPair::generate().unwrap().public_key;
            self.store
                .lock()
                .unwrap()
                .add_device(self.account, "d", &key, 1)
                .unwrap();
            key
        }

        fn device_id(&self, key: &str) -> i64 {
            self.store
                .lock()
                .unwrap()
                .devices()
                .unwrap()
                .into_iter()
                .find(|d| d.public_key == key)
                .unwrap()
                .id
        }

        async fn pass(&self) {
            self.poller.pass().await;
        }

        fn advance(&self, secs: u64) {
            self.clock.fetch_add(secs, Ordering::SeqCst);
        }

        fn view(&self, name: &str) -> NodeView {
            let now = self.clock.load(Ordering::SeqCst);
            self.poller
                .board()
                .snapshot(now)
                .nodes
                .into_iter()
                .find(|v| v.name == name)
                .unwrap_or_else(|| panic!("{name} is not on the board"))
        }

        fn logs(&self) -> Vec<String> {
            self.logs.lock().unwrap().clone()
        }
    }

    // ---- the first pass ----

    #[tokio::test]
    async fn a_device_added_in_the_database_is_on_the_node_after_one_pass_and_a_second_pass_sends_nothing()
     {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        let key = rig.add_device();

        rig.pass().await;

        assert!(toronto.has(&key), "the device reached the node's WireGuard");
        assert_eq!(toronto.count("GET"), 1);
        assert_eq!(toronto.count("PUT"), 1);
        let view = rig.view("toronto");
        assert_eq!(view.health, Health::Online);
        assert!(view.in_sync);
        assert_eq!(view.problem, None);
        assert_eq!(
            view.reading.as_ref().unwrap().peers_total,
            0,
            "read before the push"
        );

        rig.advance(10);
        rig.pass().await;

        assert_eq!(toronto.count("GET"), 2);
        assert_eq!(toronto.count("PUT"), 1, "nothing was sent the second time");
        assert_eq!(rig.view("toronto").reading.unwrap().peers_total, 1);
    }

    #[tokio::test]
    async fn a_nodes_location_is_on_the_board_whether_or_not_it_answered() {
        let rig = rig();
        rig.node("toronto", 0x11);
        rig.node("dallas", 0x22);
        let at = crate::closest::Location {
            lat: 43.65,
            lon: -79.38,
        };
        rig.store
            .lock()
            .unwrap()
            .set_node_location("toronto", at)
            .unwrap();
        // No secret file: the pass for dallas fails before it reaches the agent.
        std::fs::remove_file(rig.dir.join("dallas.secret")).unwrap();

        rig.pass().await;

        assert_eq!(rig.view("toronto").health, Health::Online);
        assert_eq!(rig.view("toronto").location, Some(at));
        assert_eq!(rig.view("dallas").location, None);
        rig.store
            .lock()
            .unwrap()
            .set_node_location("dallas", at)
            .unwrap();
        rig.advance(10);
        rig.pass().await;
        assert!(rig.view("dallas").reading.is_none(), "still not answering");
        assert_eq!(rig.view("dallas").location, Some(at), "read every pass");
    }

    #[tokio::test]
    async fn each_agent_gets_the_list_for_its_protocol_and_one_without_a_protocol_gets_it_as_published()
     {
        let rig = rig();
        let awg = rig.agent("toronto", 0x11, Some(Protocol::AmneziaWg));
        let wg = rig.agent("toronto-wg", 0x12, Some(Protocol::WireGuard));
        let older = rig.node("dallas", 0x22);
        let key = rig.add_device();

        rig.pass().await;

        let ranges = |node: &FakeNode| -> Vec<String> {
            node.wg
                .peers()
                .into_iter()
                .find(|(k, _)| *k == key)
                .map(|(_, ranges)| ranges)
                .unwrap_or_default()
        };
        assert_eq!(ranges(&awg), ["10.77.0.2/32"], "AmneziaWG: as published");
        assert_eq!(ranges(&wg), ["10.78.0.2/32"], "WireGuard: its own range");
        assert_eq!(
            ranges(&older),
            ["10.77.0.2/32"],
            "no protocol yet: as before"
        );
        for name in ["toronto", "toronto-wg", "dallas"] {
            assert!(rig.view(name).in_sync, "{name} holds the published version");
        }
        assert_eq!(rig.view("toronto").protocol, Some(Protocol::AmneziaWg));
        assert_eq!(rig.view("toronto-wg").protocol, Some(Protocol::WireGuard));
        assert_eq!(rig.view("dallas").protocol, None);

        rig.advance(10);
        rig.pass().await;
        assert_eq!(
            wg.count("PUT"),
            1,
            "the moved list counts as the same version"
        );
    }

    #[tokio::test]
    async fn every_node_gets_the_same_list() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        let dallas = rig.node("dallas", 0x22);
        let first = rig.add_device();
        let second = rig.add_device();

        rig.pass().await;

        for node in [&toronto, &dallas] {
            assert!(node.has(&first) && node.has(&second));
        }
        assert_eq!(rig.poller.board().snapshot(T0).list_version, Some(1));
    }

    #[tokio::test]
    async fn a_kick_takes_a_device_off_and_the_end_of_a_timed_kick_puts_it_back() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        let key = rig.add_device();
        rig.pass().await;
        assert!(toronto.has(&key));
        let id = rig.device_id(&key);

        rig.advance(10);
        rig.store
            .lock()
            .unwrap()
            .kick(id, KickEnd::At(T0 + 100), "admin", "test", T0 + 10)
            .unwrap();
        rig.pass().await;
        assert!(!toronto.has(&key), "kicked");

        rig.advance(100);
        rig.pass().await;
        assert!(toronto.has(&key), "the kick ran out");
    }

    #[tokio::test]
    async fn a_node_that_holds_the_current_version_gets_no_put_and_one_that_holds_an_older_one_does()
     {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        rig.add_device();
        rig.pass().await;
        assert_eq!(toronto.count("PUT"), 1);
        let first = rig.add_device();
        rig.advance(10);

        rig.pass().await;

        assert_eq!(toronto.count("PUT"), 2);
        assert!(toronto.has(&first));
    }

    #[tokio::test]
    async fn a_node_that_was_down_gets_the_latest_list_once_when_it_comes_back() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        rig.add_device();
        rig.pass().await;
        toronto.down.store(true, Ordering::SeqCst);

        let mut keys = Vec::new();
        for _ in 0..3 {
            keys.push(rig.add_device());
            rig.advance(10);
            rig.pass().await;
        }
        assert_eq!(rig.view("toronto").health, Health::NotResponding);
        let puts_before = toronto.count("PUT");
        toronto.down.store(false, Ordering::SeqCst);
        rig.advance(10);

        rig.pass().await;

        assert_eq!(
            toronto.count("PUT"),
            puts_before + 1,
            "one push, not one per version"
        );
        assert!(keys.iter().all(|k| toronto.has(k)));
        assert_eq!(rig.view("toronto").health, Health::Online);
    }

    // ---- a node ahead of the database ----

    #[tokio::test]
    async fn a_node_ahead_of_the_database_is_flagged_and_sent_nothing_until_the_version_is_raised()
    {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        for _ in 0..4 {
            rig.add_device();
            rig.pass().await;
            rig.advance(10);
        }
        let node_version = rig.view("toronto").reading.unwrap().desired_version;
        assert_eq!(node_version, Some(4));
        // A restored backup: the database forgot the later versions.
        rig.store
            .lock()
            .unwrap()
            .conn
            .execute("UPDATE published_list SET version = 1, content = '[]'", [])
            .unwrap();
        let puts = toronto.count("PUT");

        rig.pass().await;

        let view = rig.view("toronto");
        assert_eq!(view.health, Health::Online, "the node itself is fine");
        assert_eq!(
            view.problem,
            Some(Problem::Ahead {
                node: 4,
                database: 2
            })
        );
        assert!(!view.in_sync);
        assert_eq!(toronto.count("PUT"), puts, "nothing was sent");

        rig.store.lock().unwrap().raise_version_floor(4).unwrap();
        rig.advance(10);
        rig.pass().await;

        let view = rig.view("toronto");
        assert_eq!(view.problem, None);
        assert!(view.in_sync);
        assert_eq!(toronto.count("PUT"), puts + 1);
        assert_eq!(view.reading.unwrap().desired_version, Some(5));
    }

    // ---- when the node refuses or fails ----

    #[tokio::test]
    async fn a_wrong_secret_a_clock_two_minutes_off_and_a_replay_mark_all_read_as_refused_never_online()
     {
        // Wrong secret: the file on this side is not the node's.
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        rig.write_files("toronto", 0x99);
        for _ in 0..3 {
            rig.pass().await;
            rig.advance(10);
        }
        let view = rig.view("toronto");
        assert_eq!(view.health, Health::NotResponding);
        assert_eq!(view.problem, Some(Problem::Link(LinkProblem::Refused)));
        assert_eq!(toronto.count("PUT"), 0);

        // The right secret again: it works.
        rig.write_files("toronto", 0x11);
        rig.pass().await;
        assert_eq!(rig.view("toronto").health, Health::Online);

        // A clock two minutes off.
        toronto.skew.store(120, Ordering::SeqCst);
        rig.advance(10);
        rig.pass().await;
        assert_eq!(
            rig.view("toronto").problem,
            Some(Problem::Link(LinkProblem::Refused))
        );
        toronto.skew.store(0, Ordering::SeqCst);

        // An agent that restarted after accepting a request signed after ours.
        let rig = self::rig();
        let mark = T0 + 500;
        let fake = FakeNode::new(rig.clock.clone(), 0x11, Some(mark));
        rig.store
            .lock()
            .unwrap()
            .add_node("dallas", "192.0.2.50:8443", "Dallas", "US", 1)
            .unwrap();
        rig.write_files("dallas", 0x11);
        rig.connector
            .nodes
            .lock()
            .unwrap()
            .insert("dallas".into(), fake);
        rig.pass().await;
        assert_eq!(
            rig.view("dallas").problem,
            Some(Problem::Link(LinkProblem::Refused)),
            "signed at or before the agent's mark"
        );
        rig.advance(600);
        rig.pass().await;
        assert_eq!(
            rig.view("dallas").health,
            Health::Online,
            "later requests are fine"
        );
    }

    #[tokio::test]
    async fn a_node_whose_wireguard_cannot_be_read_is_not_online() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        rig.pass().await;
        toronto.wg.set_down(true);

        for _ in 0..3 {
            rig.advance(10);
            rig.pass().await;
        }

        let view = rig.view("toronto");
        assert_eq!(view.health, Health::NotResponding);
        assert_eq!(view.problem, Some(Problem::Link(LinkProblem::Unavailable)));
        assert_eq!(view.reading, None, "no count, not a count of 0");
        toronto.wg.set_down(false);
        rig.advance(10);
        rig.pass().await;
        assert_eq!(rig.view("toronto").health, Health::Online);
    }

    #[tokio::test]
    async fn a_list_the_node_stored_but_could_not_apply_stays_flagged_and_is_sent_again_until_it_takes()
     {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        rig.pass().await;
        toronto.wg.set_changes_fail(true);
        let key = rig.add_device();
        rig.advance(10);

        rig.pass().await;

        let view = rig.view("toronto");
        assert_eq!(view.health, Health::Online, "it answers");
        assert_eq!(view.problem, Some(Problem::Link(LinkProblem::Unavailable)));
        assert!(!view.in_sync);

        // The node now holds this version on disk, but its WireGuard does not have the
        // device. The version alone must not read as "in step".
        rig.advance(10);
        rig.pass().await;
        let view = rig.view("toronto");
        assert_eq!(
            view.problem,
            Some(Problem::Link(LinkProblem::Unavailable)),
            "still not applied"
        );
        assert!(!view.in_sync);
        assert!(!toronto.has(&key));

        toronto.wg.set_changes_fail(false);
        rig.advance(10);
        rig.pass().await;

        assert!(toronto.has(&key), "sent again, so it took at once");
        let view = rig.view("toronto");
        assert_eq!(view.problem, None);
        assert!(view.in_sync);
    }

    #[tokio::test]
    async fn a_peer_added_to_a_node_by_hand_is_removed_on_the_next_pass() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        let key = rig.add_device();
        rig.pass().await;
        let puts = toronto.count("PUT");
        toronto
            .wg
            .add_stray(&KeyPair::generate().unwrap().public_key, &["10.99.0.9/32"]);
        rig.advance(10);

        rig.pass().await;

        assert_eq!(
            toronto.count("PUT"),
            puts + 1,
            "the same version, but not the same peers"
        );
        assert_eq!(toronto.wg.peers().len(), 1);
        assert!(toronto.has(&key));
        assert!(rig.view("toronto").in_sync);
    }

    // ---- health ----

    #[tokio::test]
    async fn health_is_unknown_then_online_then_not_responding_only_after_three_failures() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        assert_eq!(
            rig.poller.board().snapshot(T0).nodes,
            Vec::new(),
            "before the first pass the board knows nothing"
        );

        toronto.down.store(true, Ordering::SeqCst);
        rig.pass().await;
        assert_eq!(
            rig.view("toronto").health,
            Health::Unknown,
            "one failure, never seen up"
        );
        toronto.down.store(false, Ordering::SeqCst);
        rig.advance(10);
        rig.pass().await;
        assert_eq!(rig.view("toronto").health, Health::Online);

        toronto.down.store(true, Ordering::SeqCst);
        for expected in [
            Health::Online,
            Health::Online,
            Health::NotResponding,
            Health::NotResponding,
        ] {
            rig.advance(10);
            rig.pass().await;
            let view = rig.view("toronto");
            assert_eq!(view.health, expected);
            assert_eq!(view.reading, None, "a failed pass has no count");
            assert_eq!(view.problem, Some(Problem::Link(LinkProblem::Unreachable)));
            assert!(view.last_good.is_some());
        }

        toronto.down.store(false, Ordering::SeqCst);
        rig.advance(10);
        rig.pass().await;
        let view = rig.view("toronto");
        assert_eq!(view.health, Health::Online, "one success is enough");
        assert_eq!(view.problem, None);
        assert!(view.reading.is_some());
        assert_eq!(view.last_good, Some(rig.clock.load(Ordering::SeqCst)));
    }

    #[tokio::test]
    async fn a_reading_that_is_more_than_a_minute_old_reads_as_unknown() {
        let rig = rig();
        rig.node("toronto", 0x11);
        rig.pass().await;
        let board = rig.poller.board();

        let fresh = board.snapshot(T0 + STALE_AFTER_SECS);
        assert_eq!(fresh.nodes[0].health, Health::Online);
        assert!(fresh.nodes[0].reading.is_some());

        let stale = board.snapshot(T0 + STALE_AFTER_SECS + 1);
        assert_eq!(stale.nodes[0].health, Health::Unknown);
        assert_eq!(stale.nodes[0].reading, None);
        assert_eq!(stale.nodes[0].title, "TORONTO", "its name is still known");
    }

    #[tokio::test]
    async fn how_long_a_reading_stays_good_follows_the_interval_so_a_slow_poll_does_not_flicker() {
        let rig = rig();
        rig.node("toronto", 0x11);
        let mut settings = Settings::new(rig.dir.clone(), Duration::from_secs(100));
        settings.node_deadline = Duration::from_secs(20);
        assert_eq!(
            settings.stale_after(),
            240,
            "two cycles of interval plus deadline"
        );
        assert_eq!(
            Settings::new(rig.dir.clone(), Duration::from_secs(10)).stale_after(),
            STALE_AFTER_SECS,
            "never under a minute"
        );
        let slow = Poller::new(
            rig.store.clone(),
            settings,
            rig.connector.clone(),
            Arc::new(|| T0),
            Arc::new(|_| {}),
        );
        slow.pass().await;
        let board = slow.board();

        assert_eq!(board.snapshot(T0 + 240).nodes[0].health, Health::Online);
        assert_eq!(board.snapshot(T0 + 241).nodes[0].health, Health::Unknown);
    }

    #[tokio::test]
    async fn the_public_snapshot_carries_names_and_health_but_no_readings() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        let key = rig.add_device();
        rig.pass().await;
        toronto.wg.connect(&key, T0 - 5, "203.0.113.5:1");
        rig.advance(10);
        rig.pass().await;

        let full = rig
            .poller
            .board()
            .snapshot(rig.clock.load(Ordering::SeqCst));
        let light = rig
            .poller
            .board()
            .snapshot_light(rig.clock.load(Ordering::SeqCst));

        assert!(full.nodes[0].reading.is_some());
        assert_eq!(light.nodes[0].reading, None);
        assert_eq!(light.nodes[0].problem, None);
        assert_eq!(light.nodes[0].health, Health::Online);
        assert_eq!(light.nodes[0].title, "TORONTO");
    }

    #[tokio::test]
    async fn the_status_snapshot_keeps_the_counts_and_the_load_but_no_device_and_no_login() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        let key = rig.add_device();
        rig.pass().await;
        toronto.wg.connect(&key, T0 - 5, "203.0.113.5:1");
        rig.advance(10);
        rig.pass().await;
        let now = rig.clock.load(Ordering::SeqCst);

        let full = rig.poller.board().snapshot(now);
        let counts = rig.poller.board().snapshot_counts(now);

        let (full, counts) = (
            full.nodes[0].reading.clone().expect("a reading"),
            counts.nodes[0].reading.clone().expect("the counts"),
        );
        assert!(!full.peers.is_empty(), "the full reading has the device");
        assert_eq!(counts.online, full.online);
        assert!(counts.online >= 1);
        assert_eq!(counts.load1, full.load1);
        assert!(
            counts.peers.is_empty(),
            "no device key, no handshake, no bytes"
        );
        assert!(counts.logins.is_none());
        let again = rig.poller.board().snapshot_counts(now);
        assert_eq!(again.nodes[0].problem, None);
        assert!(again.contacts.is_empty(), "and no remembered contact");
        assert_eq!(again.nodes[0].health, Health::Online);
    }

    #[test]
    fn the_status_snapshot_drops_devices_logins_and_problems_a_node_really_has() {
        let board = Board::new();
        board.set_for_test(
            vec![NodeView {
                name: "toronto".to_string(),
                title: "Toronto".to_string(),
                place: "Canada".to_string(),
                protocol: None,
                location: None,
                ip: "192.0.2.7".parse().unwrap(),
                health: Health::Online,
                checked_at: T0,
                last_good: Some(T0),
                reading: Some(NodeReading {
                    wg_public_key: "WGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGA=".to_string(),
                    listen_port: 51820,
                    online: 2,
                    peers_total: 3,
                    desired_version: Some(1),
                    load1: Some(0.4),
                    peers: vec![crate::link::PeerReading {
                        public_key: "KEYKEYKEYKEYKEYKEYKEYKEYKEYKEYKEYKEYKEYKEYA=".to_string(),
                        online: true,
                        handshake_age: Some(5),
                        rx: 10,
                        tx: 20,
                    }],
                    logins: Some(vec![bf_common::logins::Login {
                        at: T0,
                        user: "root".to_string(),
                        from: "203.0.113.5".parse().unwrap(),
                        key: None,
                        key_name: None,
                    }]),
                }),
                problem: Some(Problem::Internal),
                in_sync: true,
            }],
            T0,
        );

        let counts = board.snapshot_counts(T0);
        let reading = counts.nodes[0].reading.as_ref().expect("the counts stay");
        assert_eq!((reading.online, reading.load1), (2, Some(0.4)));
        assert!(reading.peers.is_empty(), "no device");
        assert!(reading.logins.is_none(), "no login");
        assert_eq!(counts.nodes[0].problem, None, "no reason text");
        assert!(counts.contacts.is_empty());
        // The full snapshot still has all of it.
        let full = board.snapshot(T0);
        assert!(full.nodes[0].problem.is_some());
        assert_eq!(full.nodes[0].reading.as_ref().unwrap().peers.len(), 1);
    }

    #[tokio::test]
    async fn the_status_snapshot_goes_stale_like_the_others() {
        let rig = rig();
        rig.node("toronto", 0x11);
        rig.pass().await;
        let late = T0 + STALE_AFTER_SECS + 1;
        let counts = rig.poller.board().snapshot_counts(late);
        assert_eq!(counts.nodes[0].health, Health::Unknown);
        assert!(counts.nodes[0].reading.is_none());
    }

    #[tokio::test]
    async fn the_board_never_holds_a_client_address() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        let key = rig.add_device();
        rig.pass().await;
        toronto.wg.connect(&key, T0 - 5, "203.0.113.77:51820");
        rig.advance(10);

        rig.pass().await;

        let view = rig.view("toronto");
        assert_eq!(view.reading.as_ref().unwrap().online, 1);
        assert!(!format!("{view:?}").contains("203.0.113"));
        assert_eq!(view.reading.unwrap().peers[0].public_key, key);
    }

    // ---- passes are independent ----

    #[tokio::test]
    async fn a_node_that_hangs_ends_at_the_deadline_and_does_not_hold_up_another() {
        let rig = rig_with(Duration::from_millis(300));
        let slow = rig.node("toronto", 0x11);
        rig.node("dallas", 0x22);
        slow.hang.store(true, Ordering::SeqCst);
        let started = std::time::Instant::now();

        rig.pass().await;

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(rig.view("dallas").health, Health::Online);
        assert_eq!(rig.view("toronto").health, Health::Unknown);
        assert_eq!(
            rig.view("toronto").problem,
            Some(Problem::Link(LinkProblem::Timeout))
        );
    }

    // ---- changes while it runs ----

    #[tokio::test]
    async fn a_replaced_secret_or_root_file_takes_effect_on_the_next_pass_and_times_keep_rising() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        rig.pass().await;
        assert_eq!(rig.connector.connects.load(Ordering::SeqCst), 1);
        rig.advance(10);
        rig.pass().await;
        assert_eq!(
            rig.connector.connects.load(Ordering::SeqCst),
            1,
            "the link is reused"
        );

        // The root file is replaced: a new link, and it still signs later times.
        std::fs::write(
            rig.dir.join("toronto.pem"),
            Authority::root("A Different Root").pem(),
        )
        .unwrap();
        rig.pass().await;

        assert_eq!(rig.connector.connects.load(Ordering::SeqCst), 2);
        assert_eq!(
            rig.view("toronto").health,
            Health::Online,
            "no refusal for a repeated time"
        );
        assert_eq!(toronto.count("GET"), 3);
        let times = toronto.times.lock().unwrap().clone();
        assert!(
            times.windows(2).all(|pair| pair[0] < pair[1]),
            "every request is signed later than the one before it, even from a new link: {times:?}"
        );
    }

    #[tokio::test]
    async fn nodes_added_disabled_enabled_and_removed_are_picked_up_on_the_next_pass() {
        let rig = rig();
        rig.node("toronto", 0x11);
        rig.pass().await;
        assert_eq!(rig.poller.board().snapshot(T0).nodes.len(), 1);

        rig.node("dallas", 0x22);
        rig.pass().await;
        let names = |rig: &Rig| -> Vec<String> {
            rig.poller
                .board()
                .snapshot(T0)
                .nodes
                .into_iter()
                .map(|n| n.name)
                .collect()
        };
        assert_eq!(names(&rig), ["toronto", "dallas"]);

        rig.store
            .lock()
            .unwrap()
            .set_node_enabled("toronto", false)
            .unwrap();
        rig.pass().await;
        assert_eq!(
            names(&rig),
            ["toronto", "dallas"],
            "a disabled node stays on the board, as being fixed"
        );
        assert_eq!(rig.view("toronto").health, Health::BeingFixed);
        assert_eq!(rig.view("dallas").health, Health::Online);

        rig.store
            .lock()
            .unwrap()
            .set_node_enabled("toronto", true)
            .unwrap();
        rig.pass().await;
        assert_eq!(names(&rig), ["toronto", "dallas"]);
        assert_eq!(rig.view("toronto").health, Health::Online);

        rig.store.lock().unwrap().remove_node("dallas").unwrap();
        rig.pass().await;
        assert_eq!(names(&rig), ["toronto"]);
    }

    #[tokio::test]
    async fn a_disabled_node_is_on_the_board_as_being_fixed_with_no_reading_and_is_never_called() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        rig.pass().await;
        assert_eq!(rig.view("toronto").health, Health::Online);
        let before = toronto.requests.lock().unwrap().len();
        assert!(before > 0);

        rig.store
            .lock()
            .unwrap()
            .set_node_enabled("toronto", false)
            .unwrap();
        for _ in 0..3 {
            rig.advance(10);
            rig.pass().await;
        }

        let view = rig.view("toronto");
        assert_eq!(view.health, Health::BeingFixed);
        assert_eq!(view.title, "TORONTO");
        assert_eq!(view.place, "Somewhere");
        assert!(view.reading.is_none(), "there is no count of 0, just none");
        assert!(view.problem.is_none(), "switched off is not a fault");
        assert!(!view.in_sync);
        assert_eq!(
            toronto.requests.lock().unwrap().len(),
            before,
            "the poller does not call a node that is switched off"
        );
        assert!(
            rig.logs()
                .iter()
                .all(|line| !line.contains("not responding")),
            "{:?}",
            rig.logs()
        );
    }

    #[tokio::test]
    async fn a_node_disabled_before_it_was_ever_set_up_needs_no_files_and_raises_no_problem() {
        let rig = rig();
        rig.store
            .lock()
            .unwrap()
            .add_node("dallas", "192.0.2.9:8443", "Dallas", "United States", 1)
            .unwrap();
        rig.store
            .lock()
            .unwrap()
            .set_node_enabled("dallas", false)
            .unwrap();
        rig.pass().await;

        let view = rig.view("dallas");
        assert_eq!(view.health, Health::BeingFixed);
        assert_eq!(view.ip, "192.0.2.9".parse::<std::net::IpAddr>().unwrap());
        assert!(view.problem.is_none());
        assert!(rig.logs().is_empty(), "{:?}", rig.logs());
    }

    #[tokio::test]
    async fn a_node_that_is_enabled_again_starts_from_nothing_not_from_before_it_was_switched_off()
    {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        rig.pass().await;
        toronto.down.store(true, Ordering::SeqCst);
        for _ in 0..3 {
            rig.advance(10);
            rig.pass().await;
        }
        assert_eq!(rig.view("toronto").health, Health::NotResponding);

        rig.store
            .lock()
            .unwrap()
            .set_node_enabled("toronto", false)
            .unwrap();
        rig.advance(10);
        rig.pass().await;
        assert_eq!(rig.view("toronto").health, Health::BeingFixed);

        toronto.down.store(false, Ordering::SeqCst);
        rig.store
            .lock()
            .unwrap()
            .set_node_enabled("toronto", true)
            .unwrap();
        rig.advance(10);
        rig.pass().await;
        assert_eq!(rig.view("toronto").health, Health::Online);
    }

    #[tokio::test]
    async fn a_node_that_moves_to_another_address_gets_a_new_link() {
        let rig = rig();
        rig.node("toronto", 0x11);
        rig.pass().await;
        assert_eq!(rig.connector.connects.load(Ordering::SeqCst), 1);

        rig.store
            .lock()
            .unwrap()
            .conn
            .execute(
                "UPDATE nodes SET address = '198.51.100.9:8443' WHERE name = 'toronto'",
                [],
            )
            .unwrap();
        rig.advance(10);
        rig.pass().await;

        assert_eq!(rig.connector.connects.load(Ordering::SeqCst), 2);
        assert_eq!(rig.view("toronto").health, Health::Online);
    }

    #[tokio::test]
    async fn a_node_that_is_removed_and_added_again_starts_from_nothing() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        rig.pass().await;
        assert_eq!(rig.view("toronto").health, Health::Online);
        rig.store.lock().unwrap().remove_node("toronto").unwrap();
        rig.pass().await;
        rig.store
            .lock()
            .unwrap()
            .add_node("toronto", "192.0.2.1:8443", "Toronto", "Canada", 5)
            .unwrap();
        toronto.down.store(true, Ordering::SeqCst);

        rig.pass().await;

        assert_eq!(
            rig.view("toronto").health,
            Health::Unknown,
            "the old Online did not survive the removal"
        );
    }

    #[tokio::test]
    async fn a_node_without_its_files_does_not_stop_the_others_and_says_why() {
        let rig = rig();
        rig.node("toronto", 0x11);
        rig.node("dallas", 0x22);
        std::fs::remove_file(rig.dir.join("toronto.secret")).unwrap();

        for _ in 0..3 {
            rig.pass().await;
            rig.advance(10);
        }

        assert_eq!(rig.view("dallas").health, Health::Online);
        let view = rig.view("toronto");
        assert_eq!(view.health, Health::NotResponding);
        assert_eq!(
            view.problem,
            Some(Problem::Files(FilesProblem::SecretMissing))
        );
    }

    // ---- the log ----

    #[tokio::test]
    async fn the_log_has_a_line_for_each_change_none_for_a_quiet_pass_and_no_secret_or_key() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        let key = rig.add_device();

        rig.pass().await;
        let after_first = rig.logs();
        assert_eq!(after_first.len(), 2, "{after_first:?}");
        assert!(
            after_first
                .iter()
                .any(|l| l.contains("toronto") && l.contains("online"))
        );
        assert!(
            after_first
                .iter()
                .any(|l| l.contains("list version 1 sent"))
        );

        rig.advance(10);
        rig.pass().await;
        rig.advance(10);
        rig.pass().await;
        assert_eq!(rig.logs(), after_first, "quiet passes write nothing");

        toronto.down.store(true, Ordering::SeqCst);
        for _ in 0..5 {
            rig.advance(10);
            rig.pass().await;
        }
        toronto.down.store(false, Ordering::SeqCst);
        rig.advance(10);
        rig.pass().await;

        let lines = rig.logs();
        assert_eq!(lines.len(), after_first.len() + 2, "{lines:?}");
        assert!(lines[2].contains("not responding"), "{lines:?}");
        assert!(lines[3].ends_with("online"), "{lines:?}");
        let everything = lines.join("\n");
        assert!(!everything.contains(&secret_hex(0x11)));
        assert!(!everything.contains(&key));
        assert!(!everything.contains("1111"));
    }

    // ---- running ----

    #[tokio::test]
    async fn a_poke_makes_the_running_poller_pass_now_instead_of_waiting_for_the_interval() {
        let rig = rig();
        let toronto = rig.node("toronto", 0x11);
        let runner = tokio::spawn(rig.poller.clone().run());
        let wait_for = |what: &'static str, ok: Box<dyn Fn() -> bool>| async move {
            for _ in 0..200 {
                if ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("timed out waiting for {what}");
        };
        let seen = toronto.clone();
        wait_for("the first pass", Box::new(move || seen.count("GET") >= 1)).await;

        let key = rig.add_device();
        rig.advance(10);
        rig.poller.poke();

        let seen = toronto.clone();
        let wanted = key.clone();
        wait_for("the poked pass", Box::new(move || seen.has(&wanted))).await;
        runner.abort();
    }

    // ---- the interval setting ----

    #[test]
    fn the_interval_is_ten_seconds_unless_set_and_must_be_two_to_three_hundred() {
        assert_eq!(poll_interval(None), Ok(Duration::from_secs(10)));
        assert_eq!(poll_interval(Some("2")), Ok(Duration::from_secs(2)));
        assert_eq!(poll_interval(Some("300")), Ok(Duration::from_secs(300)));
        for bad in [
            "",
            "1",
            "0",
            "301",
            "-5",
            "ten",
            "10s",
            " 10",
            "10 ",
            "1.5",
            "+5",
            "99999999999999999999",
        ] {
            assert!(poll_interval(Some(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn health_has_the_words_the_public_page_uses() {
        assert_eq!(Health::Online.label(), "Online");
        assert_eq!(Health::NotResponding.label(), "Not responding");
        assert_eq!(Health::Unknown.label(), "Status unknown");
        let _: HashSet<u8> = HashSet::new();
    }
}

//! A node for tests: the real agent behind a fake `wg`, reached without a network. The poller
//! and the admin commands are tested against it, so what they see is what the agent says.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bf_agent::service::{Agent, Request};
use bf_agent::testutil::{FakeWg, TempDir};
use bf_common::sign::unhex;

use crate::link::{
    BoxFuture, FilesProblem, Incoming, Link, LinkProblem, NodeFiles, Outgoing, Transport,
};
use crate::nodes::Node;
use crate::poller::Connector;

pub const T0: u64 = 1_700_000_000;

pub fn secret_hex(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

/// A node with the real agent inside and a fake `wg`, reached without a network.
pub struct FakeNode {
    pub agent: Agent,
    pub wg: Arc<FakeWg>,
    pub clock: Arc<AtomicU64>,
    /// How far the node's clock is from ours, in seconds.
    pub skew: AtomicI64,
    pub down: AtomicBool,
    pub hang: AtomicBool,
    /// The one-minute load the node reports (0.1 unless a test sets it).
    pub load: Mutex<Option<f64>>,
    pub requests: Mutex<Vec<String>>,
    /// The time each request was signed at.
    pub times: Mutex<Vec<u64>>,
    _dir: TempDir,
}

impl FakeNode {
    pub fn new(clock: Arc<AtomicU64>, secret_byte: u8, mark: Option<u64>) -> Arc<FakeNode> {
        let dir = TempDir::new("poller-node");
        let wg = Arc::new(FakeWg::default());
        let store = bf_agent::store::Store::new(dir.path().to_path_buf());
        if let Some(mark) = mark {
            store.save_replay_mark(mark).unwrap();
        }
        let agent = Agent::new_at(
            wg.clone(),
            store,
            unhex(&secret_hex(secret_byte)).unwrap(),
            180,
            T0 - 1_000,
        );
        Arc::new(FakeNode {
            agent,
            wg,
            clock,
            skew: AtomicI64::new(0),
            down: AtomicBool::new(false),
            load: Mutex::new(Some(0.1)),
            hang: AtomicBool::new(false),
            requests: Mutex::default(),
            times: Mutex::default(),
            _dir: dir,
        })
    }

    pub fn count(&self, what: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with(what))
            .count()
    }

    pub fn has(&self, key: &str) -> bool {
        self.wg.has_peer(key)
    }
}

pub struct LocalTransport(Arc<FakeNode>);

impl Transport for LocalTransport {
    fn send<'a>(&'a self, out: Outgoing<'a>) -> BoxFuture<'a, Result<Incoming, LinkProblem>> {
        let node = self.0.clone();
        Box::pin(async move {
            node.requests
                .lock()
                .unwrap()
                .push(format!("{} {}", out.method, out.path));
            node.times.lock().unwrap().push(out.time);
            if node.hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if node.down.load(Ordering::SeqCst) {
                return Err(LinkProblem::Unreachable);
            }
            let now = node.clock.load(Ordering::SeqCst) as i64 + node.skew.load(Ordering::SeqCst);
            let time = out.time.to_string();
            let reply = node.agent.handle(
                now as u64,
                *node.load.lock().unwrap(),
                &Request {
                    method: out.method,
                    path_and_query: out.path,
                    time: Some(&time),
                    nonce: Some(out.nonce),
                    signature: Some(out.signature),
                    body: out.body,
                },
            );
            Ok(Incoming {
                status: reply.status,
                body: reply.body.into_bytes(),
            })
        })
    }
}

#[derive(Default)]
pub struct FakeConnector {
    pub nodes: Mutex<HashMap<String, Arc<FakeNode>>>,
    pub connects: AtomicUsize,
}

impl Connector for FakeConnector {
    fn connect(&self, node: &Node, files: &NodeFiles) -> Result<Link, FilesProblem> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        let fake = self
            .nodes
            .lock()
            .unwrap()
            .get(&node.name)
            .cloned()
            .expect("a fake node");
        Ok(Link::new(
            Arc::new(LocalTransport(fake)),
            files.secret().to_vec(),
        ))
    }
}

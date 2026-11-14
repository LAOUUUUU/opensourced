//! Helpers shared by the agent's tests.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bf_common::peers::Cidr;

use crate::wgcli::{WgError, Wireguard};

/// Valid WireGuard keys for fixtures: 32 bytes of 0x01, 0x02, 0x03 and 0x04 in base64.
pub const K1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
pub const K2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
pub const K3: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
pub const K4: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=";

/// Secrets the fake interface holds. Nothing the agent says may contain them.
pub const PRIVATE_KEY: &str = "FAKE-PRIVATE-KEY-MUST-NEVER-BE-SHOWN";
pub const PRESHARED_KEY: &str = "FAKE-PRESHARED-KEY-MUST-NEVER-BE-SHOWN";
pub const NODE_PUBLIC_KEY: &str = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=";

struct FakePeer {
    key: String,
    ranges: Vec<String>,
    handshake: u64,
    endpoint: String,
    rx: u64,
}

#[derive(Default)]
struct FakeInner {
    peers: Vec<FakePeer>,
    calls: Vec<String>,
    down: bool,
    changes_fail: bool,
    sets_fail: bool,
    delay: Duration,
}

/// A pretend WireGuard interface. It keeps its peers in memory, prints them in the format
/// of `wg show dump` (with a private key and preshared keys, like the real one) and
/// records every call that changes something.
#[derive(Default)]
pub struct FakeWg {
    inner: Mutex<FakeInner>,
}

impl FakeWg {
    pub fn with_peers(peers: &[(&str, &[&str])]) -> Self {
        let fake = Self::default();
        for (key, ranges) in peers {
            fake.lock().peers.push(FakePeer {
                key: (*key).to_string(),
                ranges: ranges.iter().map(ToString::to_string).collect(),
                handshake: 0,
                endpoint: "(none)".to_string(),
                rx: 0,
            });
        }
        fake
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeInner> {
        self.inner.lock().unwrap()
    }

    /// The calls that changed something, such as `remove <key>` or `set <key> <ranges>`.
    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.clone()
    }

    pub fn peers(&self) -> Vec<(String, Vec<String>)> {
        self.lock()
            .peers
            .iter()
            .map(|p| (p.key.clone(), p.ranges.clone()))
            .collect()
    }

    /// Makes every `wg set` take this long (without holding the fake's own lock, like a
    /// slow kernel call would not hold up `wg show`).
    pub fn set_delay(&self, delay: Duration) {
        self.lock().delay = delay;
    }

    fn wait_if_slow(&self) {
        let delay = self.lock().delay;
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
    }

    /// Adds a peer behind the agent's back, like a restarted interface or an operator
    /// would. It is not recorded as a call.
    pub fn add_stray(&self, key: &str, ranges: &[&str]) {
        self.lock().peers.push(FakePeer {
            key: key.to_string(),
            ranges: ranges.iter().map(ToString::to_string).collect(),
            handshake: 0,
            endpoint: "(none)".to_string(),
            rx: 0,
        });
    }

    pub fn has_peer(&self, key: &str) -> bool {
        self.lock().peers.iter().any(|peer| peer.key == key)
    }

    /// Pretends the interface is gone: every call fails.
    pub fn set_down(&self, down: bool) {
        self.lock().down = down;
    }

    /// Pretends `wg set` fails while `wg show` still works.
    pub fn set_changes_fail(&self, fail: bool) {
        self.lock().changes_fail = fail;
    }

    /// Pretends only `wg set ... allowed-ips` fails (a remove still works).
    pub fn set_sets_fail(&self, fail: bool) {
        self.lock().sets_fail = fail;
    }

    /// Pretends the peer sent `bytes` more (a handshake or data).
    pub fn receive(&self, key: &str, bytes: u64) {
        let mut inner = self.lock();
        let peer = inner
            .peers
            .iter_mut()
            .find(|p| p.key == key)
            .expect("known peer");
        peer.rx += bytes;
    }

    pub fn connect(&self, key: &str, handshake: u64, endpoint: &str) {
        let mut inner = self.lock();
        let peer = inner
            .peers
            .iter_mut()
            .find(|p| p.key == key)
            .expect("known peer");
        peer.handshake = handshake;
        peer.endpoint = endpoint.to_string();
    }
}

impl Wireguard for FakeWg {
    fn dump(&self) -> Result<String, WgError> {
        let inner = self.lock();
        if inner.down {
            return Err(WgError("wg show failed (fake)".to_string()));
        }
        let mut text = format!("{PRIVATE_KEY}\t{NODE_PUBLIC_KEY}\t51820\toff\n");
        for peer in &inner.peers {
            let ranges = if peer.ranges.is_empty() {
                "(none)".to_string()
            } else {
                peer.ranges.join(",")
            };
            text.push_str(&format!(
                "{}\t{PRESHARED_KEY}\t{}\t{ranges}\t{}\t{}\t0\toff\n",
                peer.key, peer.endpoint, peer.handshake, peer.rx
            ));
        }
        Ok(text)
    }

    fn remove_peer(&self, public_key: &str) -> Result<(), WgError> {
        self.wait_if_slow();
        let mut inner = self.lock();
        if inner.down || inner.changes_fail {
            return Err(WgError("wg set failed (fake)".to_string()));
        }
        inner.calls.push(format!("remove {public_key}"));
        inner.peers.retain(|p| p.key != public_key);
        Ok(())
    }

    fn set_peer(&self, public_key: &str, ranges: &[Cidr]) -> Result<(), WgError> {
        self.wait_if_slow();
        let mut inner = self.lock();
        if inner.down || inner.changes_fail || inner.sets_fail {
            return Err(WgError("wg set failed (fake)".to_string()));
        }
        let ranges: Vec<String> = ranges.iter().map(ToString::to_string).collect();
        inner
            .calls
            .push(format!("set {public_key} {}", ranges.join(",")));
        match inner.peers.iter_mut().find(|p| p.key == public_key) {
            Some(peer) => peer.ranges = ranges,
            None => inner.peers.push(FakePeer {
                key: public_key.to_string(),
                ranges,
                handshake: 0,
                endpoint: "(none)".to_string(),
                rx: 0,
            }),
        }
        Ok(())
    }
}

/// A pretend tracker switch: records every set it is asked to hold, and can be told to
/// fail.
#[derive(Default)]
pub struct FakeSet {
    calls: Mutex<Vec<Vec<std::net::Ipv4Addr>>>,
    fails: std::sync::atomic::AtomicBool,
}

impl FakeSet {
    /// Every set asked for, oldest first.
    pub fn calls(&self) -> Vec<Vec<std::net::Ipv4Addr>> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn fail(&self, fails: bool) {
        self.fails.store(fails, Ordering::SeqCst);
    }
}

impl crate::nft::TrackerSet for FakeSet {
    fn replace(&self, off: &[std::net::Ipv4Addr]) -> Result<(), WgError> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(off.to_vec());
        if self.fails.load(Ordering::SeqCst) {
            return Err(WgError(
                "nft -f failed (exit status: 1): Error: No such file or directory".to_string(),
            ));
        }
        Ok(())
    }
}

/// A fresh directory that is removed when it goes out of scope.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bf-agent-test-{}-{}-{}",
            std::process::id(),
            label,
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create the test directory");
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

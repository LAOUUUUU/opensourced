//! The agent itself: checks a request's signature, then answers `GET /v1/status` or
//! `PUT /v1/peers`. It knows nothing about HTTP libraries; the server hands it a
//! [`Request`] and sends back the [`Reply`].

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bf_common::peers::{Desired, PeerList, Verdict, judge};
use bf_common::sign::{Parts, Verifier, WINDOW_SECS};
use bf_common::status::build_status;
use bf_common::wg::{FORGET_IDLE_AFTER_SECS, parse_dump};
use serde::Serialize;
use serde_json::json;

use crate::logins::LoginLog;
use crate::nft::TrackerSet;
use crate::reconcile::{Changes, Quiet, apply, forget_idle};
use crate::store::Store;
use crate::wgcli::{WgError, Wireguard};

/// A request as the server saw it. The three header values are the raw `X-BF-Time`,
/// `X-BF-Nonce` and `X-BF-Sig` headers, `None` if missing.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub time: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub signature: Option<&'a str>,
    pub body: &'a [u8],
}

/// What to send back: a status code and a JSON body (empty for the plain 404).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub body: String,
}

impl Reply {
    /// The one answer to everything that is not a valid, signed request for a real path.
    pub fn not_found() -> Reply {
        Reply {
            status: 404,
            body: String::new(),
        }
    }

    fn json(status: u16, value: &impl Serialize) -> Reply {
        Reply {
            status,
            body: serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()),
        }
    }

    /// WireGuard could not be read or changed. Never an empty answer that looks like zero.
    fn unavailable() -> Reply {
        Reply::json(503, &serde_json::json!({ "error": "unavailable" }))
    }
}

fn log(message: &str) {
    crate::log::line(message);
}

/// Makes WireGuard match the stored list when it starts and then every `every`. A pass
/// that fails is logged, and the next one tries again.
pub async fn keep_matching(agent: Arc<Agent>, every: Duration) {
    let mut tick = tokio::time::interval(every);
    loop {
        tick.tick().await;
        // First the server lets go of the addresses of devices that have gone quiet; then
        // the list pass, which also puts back a device whose forgetting broke halfway. The
        // line says how many, never which.
        let forgetting = agent.clone();
        match tokio::task::spawn_blocking(move || forgetting.forget_idle(unix_now())).await {
            Ok(Ok(Some(n))) if n > 0 => log(&format!("forgot {n} idle device(s)")),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => log(&format!("forgetting idle devices failed: {e}")),
            Err(e) => log(&format!("forgetting idle devices panicked: {e}")),
        }
        let passing = agent.clone();
        match tokio::task::spawn_blocking(move || passing.reconcile()).await {
            Ok(Ok(Some(changes))) if changes != Changes::default() => log(&format!(
                "reconcile: added {}, removed {}, updated {}",
                changes.added, changes.removed, changes.updated
            )),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => log(&format!("reconcile failed: {e}")),
            Err(e) => log(&format!("reconcile pass panicked: {e}")),
        }
    }
}

/// The clock in Unix seconds (0 if it reads before 1970, so no handshake looks old).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Takes a lock even if a panic elsewhere poisoned it: the data behind these locks stays
/// valid, and the agent must keep answering.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The answer to a list that was accepted.
#[derive(Serialize)]
struct Applied {
    version: u64,
    #[serde(flatten)]
    changes: Changes,
}

/// The agent. It has three locks, and a slow `wg` call can hold up only the one that is
/// about changing things:
/// - `verifier` is held only while a signature is checked, so refusals never wait;
/// - `stored` is held only to read or replace the list;
/// - `changing` makes PUT and the reconcile pass take turns. It is held across `wg` calls,
///   which have a deadline. Status takes none of the three while it talks to `wg`.
///
/// A fourth, `marked`, is held for the few bytes it takes to write the replay mark (see
/// [`Agent::new_at`]) and only by requests that passed the signature check.
pub struct Agent {
    wg: Arc<dyn Wireguard>,
    store: Store,
    online_secs: u64,
    verifier: Mutex<Verifier>,
    stored: Mutex<Option<Desired>>,
    changing: Mutex<()>,
    /// The highest request time written to disk as the replay mark so far.
    marked: Mutex<u64>,
    /// The per-device tracker switch, when this node has one (`specs/trackers.md`).
    trackers: Option<Arc<dyn TrackerSet>>,
    /// Whether the last change of the switch failed, so a failure is logged once when it
    /// starts and once when it ends, not on every pass.
    trackers_failing: Mutex<bool>,
    /// What each peer looked like at the last forgetting pass (`reconcile::forget_idle`).
    quiet: Mutex<Quiet>,
    /// Where the recent SSH logins come from (`specs/login-alerts.md`); none means the
    /// status carries no logins.
    logins: Option<Arc<dyn LoginLog>>,
    /// Whether the last reading of the logins failed, so it is logged once, not every poll.
    logins_failing: Mutex<bool>,
    /// The same for the attention file (decision 031).
    attention_failing: Mutex<bool>,
}

impl Agent {
    /// Starts with the list found in `store`, if any. A list that cannot be read is
    /// reported and treated as no list, which leaves WireGuard alone.
    pub fn new(wg: Arc<dyn Wireguard>, store: Store, secret: Vec<u8>, online_secs: u64) -> Agent {
        Agent::new_at(wg, store, secret, online_secs, 0)
    }

    /// Like [`Agent::new`], for a process that starts at `started_at` (Unix seconds).
    ///
    /// The nonces the verifier remembers are lost in a restart, so a copy of a request
    /// accepted just before could be accepted again. To close that gap the agent keeps the
    /// highest request time it has accepted on disk (the replay mark, written before the
    /// request is acted on) and, after a restart, refuses every request signed at or before
    /// it. Without a mark file (the first start of a build that has this) the floor is
    /// `started_at`; with a mark file that cannot be read it is a minute after
    /// `started_at`, which is long enough for any older request to leave the window.
    pub fn new_at(
        wg: Arc<dyn Wireguard>,
        store: Store,
        secret: Vec<u8>,
        online_secs: u64,
        started_at: u64,
    ) -> Agent {
        let stored = match store.load() {
            Ok(Some(list)) => match list.check() {
                Ok(desired) => Some(desired),
                Err(e) => {
                    log(&format!(
                        "the stored peer list is invalid and is ignored: {e}"
                    ));
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                log(&format!(
                    "the stored peer list cannot be read and is ignored: {e:?}"
                ));
                None
            }
        };
        let (floor, marked) = match store.load_replay_mark() {
            Ok(Some(mark)) => (mark, mark),
            Ok(None) => (started_at, 0),
            Err(e) => {
                log(&format!(
                    "the replay mark cannot be read ({e:?}); refusing requests for one minute"
                ));
                (started_at.saturating_add(WINDOW_SECS), 0)
            }
        };
        if floor > 0 {
            log(&format!(
                "refusing requests signed at or before {floor} (copies of ones accepted before this start)"
            ));
        }
        Agent {
            wg,
            store,
            online_secs,
            verifier: Mutex::new(Verifier::with_floor(secret, floor)),
            stored: Mutex::new(stored),
            changing: Mutex::new(()),
            marked: Mutex::new(marked),
            trackers: None,
            trackers_failing: Mutex::new(false),
            logins: None,
            logins_failing: Mutex::new(false),
            attention_failing: Mutex::new(false),
            quiet: Mutex::new(Quiet::new()),
        }
    }

    /// Puts the recent SSH logins from `log` in every status.
    #[must_use]
    pub fn with_login_log(mut self, log: Arc<dyn LoginLog>) -> Agent {
        self.logins = Some(log);
        self
    }

    /// The logins for a status at `now`, or `None`; a failure is logged when it starts and
    /// when it ends.
    fn recent_logins(&self, now: u64) -> Option<Vec<bf_common::logins::Login>> {
        let logins = self.logins.as_ref()?.recent(now);
        let mut failing = lock(&self.logins_failing);
        match (&logins, *failing) {
            (Err(why), false) => {
                log(&format!("logins: {why}; the status carries none"));
                *failing = true;
            }
            (Ok(_), true) => {
                log("logins: read again");
                *failing = false;
            }
            _ => {}
        }
        logins.ok()
    }

    /// What needs attention for a status at `now` (decision 031), or `None`; a failure (a
    /// stale or unreadable file) is logged when it starts and when it ends.
    fn attention(&self, now: u64) -> Option<bf_common::attention::Attention> {
        let news = self.logins.as_ref()?.attention(now);
        let mut failing = lock(&self.attention_failing);
        match (&news, *failing) {
            (Err(why), false) => {
                log(&format!("attention: {why}; the status carries none"));
                *failing = true;
            }
            (Ok(_), true) => {
                log("attention: read again");
                *failing = false;
            }
            _ => {}
        }
        news.ok().flatten()
    }

    /// Keeps `set` in step with the list: after each list is applied and on every pass.
    #[must_use]
    pub fn with_tracker_set(mut self, set: Arc<dyn TrackerSet>) -> Agent {
        self.trackers = Some(set);
        self
    }

    /// Makes the switch hold the IPv4 addresses of the peers whose trackers are not
    /// blocked. A failure is logged and changes nothing else; the next pass tries again.
    fn sync_trackers(&self, desired: &Desired) {
        let Some(set) = &self.trackers else {
            return;
        };
        let off: Vec<std::net::Ipv4Addr> = desired
            .peers
            .iter()
            .filter(|peer| !peer.trackers)
            .flat_map(|peer| peer.ranges.iter().filter_map(|range| range.ipv4_host()))
            .collect();
        let result = set.replace(&off);
        let mut failing = lock(&self.trackers_failing);
        match result {
            Err(e) if !*failing => {
                log(&format!("trackers: cannot update the switch: {e}"));
                *failing = true;
            }
            Ok(()) if *failing => {
                log("trackers: the switch is updated again");
                *failing = false;
            }
            _ => {}
        }
    }

    /// Writes the highest accepted time to disk if it has gone up. A failure is logged and
    /// the request is still served: the agent stays up, and only a restart before the next
    /// successful write could accept a copy of a request from the last minute.
    fn remember(&self, highest: u64) {
        let mut marked = lock(&self.marked);
        if highest > *marked {
            match self.store.save_replay_mark(highest) {
                Ok(()) => *marked = highest,
                Err(e) => log(&format!(
                    "cannot store the replay mark ({e:?}); a restart could accept a copy of a recent request"
                )),
            }
        }
    }

    /// Answers one request. `now` is the clock in Unix seconds, `load1` the one-minute
    /// load average if it could be read.
    pub fn handle(&self, now: u64, load1: Option<f64>, request: &Request<'_>) -> Reply {
        self.handle_with(|| now, load1, request)
    }

    /// Like [`Agent::handle`], but reads the clock itself. The verifier gets its time while
    /// it holds the verifier lock, so it sees time only ever move forward, even when
    /// requests queue up behind each other.
    pub fn handle_with(
        &self,
        clock: impl Fn() -> u64,
        load1: Option<f64>,
        request: &Request<'_>,
    ) -> Reply {
        let (Some(time), Some(nonce), Some(signature)) =
            (request.time, request.nonce, request.signature)
        else {
            return Reply::not_found();
        };
        let Ok(time) = time.parse::<u64>() else {
            return Reply::not_found();
        };
        let parts = Parts {
            method: request.method,
            path_and_query: request.path_and_query,
            time,
            nonce,
            body: request.body,
        };
        let accepted = {
            let mut verifier = lock(&self.verifier);
            if verifier.verify(clock(), &parts, signature).is_err() {
                return Reply::not_found();
            }
            verifier.highest_accepted()
        };
        // On disk before anything is done for the request, so no request is ever acted on
        // without a copy of it being refused after a restart.
        self.remember(accepted);
        match (request.method, request.path_and_query) {
            ("GET", "/v1/status") => self.status(clock(), load1),
            ("PUT", "/v1/peers") => self.put_peers(request.body),
            _ => Reply::not_found(),
        }
    }

    fn put_peers(&self, body: &[u8]) -> Reply {
        let Ok(list) = serde_json::from_slice::<PeerList>(body) else {
            return Reply::json(400, &json!({ "error": "bad_request" }));
        };
        let desired = match list.check() {
            Ok(desired) => desired,
            Err(e) => {
                return Reply::json(
                    400,
                    &json!({ "error": "bad_list", "detail": e.to_string() }),
                );
            }
        };
        // One change at a time: wait for any PUT or reconcile pass that is running.
        let _changing = lock(&self.changing);
        let current = lock(&self.stored).clone();
        match judge(current.as_ref(), &desired) {
            Verdict::Stale => {
                let stored_version = current.as_ref().map(|stored| stored.version);
                return Reply::json(
                    409,
                    &json!({ "error": "stale", "stored_version": stored_version }),
                );
            }
            Verdict::Newer => {
                // On disk first: if applying fails or the agent restarts, the list is not lost.
                if let Err(e) = self.store.save(&list) {
                    log(&format!(
                        "peers: cannot store version {}: {e:?}",
                        desired.version
                    ));
                    return Reply::json(500, &json!({ "error": "store_failed" }));
                }
                *lock(&self.stored) = Some(desired.clone());
            }
            Verdict::Repeat => {}
        }
        let applied = apply(&*self.wg, &desired);
        self.sync_trackers(&desired);
        match applied {
            Ok(changes) => Reply::json(
                200,
                &Applied {
                    version: desired.version,
                    changes,
                },
            ),
            Err(e) => {
                log(&format!(
                    "peers: applying version {} failed: {e}",
                    desired.version
                ));
                Reply::unavailable()
            }
        }
    }

    fn status(&self, now: u64, load1: Option<f64>) -> Reply {
        let dump = self
            .wg
            .dump()
            .map_err(|e| e.0)
            .and_then(|text| parse_dump(&text).map_err(|e| e.to_string()));
        let dump = match dump {
            Ok(dump) => dump,
            Err(why) => {
                log(&format!("status: WireGuard unavailable: {why}"));
                return Reply::unavailable();
            }
        };
        let desired_version = lock(&self.stored).as_ref().map(|desired| desired.version);
        let mut status = build_status(now, &dump, self.online_secs, desired_version, load1);
        status.logins = self.recent_logins(now);
        status.attention = self.attention(now);
        Reply::json(200, &status)
    }

    /// Forgets the devices with no handshake for [`FORGET_IDLE_AFTER_SECS`] at `now`, so the
    /// server no longer holds their addresses (`reconcile::forget_idle`). Like a pass, it
    /// waits for any change in progress and does nothing at all with no list. Gives how many
    /// were forgotten.
    pub fn forget_idle(&self, now: u64) -> Result<Option<usize>, WgError> {
        let _changing = lock(&self.changing);
        let Some(desired) = lock(&self.stored).clone() else {
            return Ok(None);
        };
        forget_idle(
            &*self.wg,
            &desired,
            now,
            FORGET_IDLE_AFTER_SECS,
            &mut lock(&self.quiet),
        )
        .map(Some)
    }

    /// Makes WireGuard match the stored list again. With no list it does nothing at all.
    pub fn reconcile(&self) -> Result<Option<Changes>, WgError> {
        let _changing = lock(&self.changing);
        let desired = lock(&self.stored).clone();
        match desired {
            None => Ok(None),
            Some(desired) => {
                let applied = apply(&*self.wg, &desired);
                self.sync_trackers(&desired);
                applied.map(Some)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use bf_common::peers::PeerList;
    use bf_common::sign::{Parts, sign, unhex};
    use serde_json::{Value, json};

    use super::*;
    use crate::testutil::{FakeSet, FakeWg, K1, K2, K3, K4, PRESHARED_KEY, PRIVATE_KEY, TempDir};
    use std::net::Ipv4Addr;

    const SECRET_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const NOW: u64 = 1_794_280_000;

    fn secret() -> Vec<u8> {
        unhex(SECRET_HEX).unwrap()
    }

    /// A correctly signed request for some other method or path, with its own nonce.
    struct Extra {
        nonce: &'static str,
        method: &'static str,
        path: &'static str,
        signature: String,
    }

    impl Extra {
        fn signed(nonce: &'static str, method: &'static str, path: &'static str) -> Extra {
            let parts = Parts {
                method,
                path_and_query: path,
                time: NOW,
                nonce,
                body: b"",
            };
            Extra {
                nonce,
                method,
                path,
                signature: sign(&secret(), &parts),
            }
        }

        fn request<'a>(&'a self, base: &Request<'a>) -> Request<'a> {
            Request {
                method: self.method,
                path_and_query: self.path,
                nonce: Some(self.nonce),
                signature: Some(&self.signature),
                ..*base
            }
        }
    }

    /// An agent over a fake interface, plus a way to send it correctly signed requests.
    struct Rig {
        agent: Agent,
        wg: Arc<FakeWg>,
        counter: AtomicU64,
        dir: TempDir,
    }

    impl Rig {
        fn new(wg: FakeWg) -> Rig {
            Rig::new_with(wg, |agent, _| agent)
        }

        /// Like [`Rig::new`], with something more done to the agent (given the rig's folder).
        fn new_with(wg: FakeWg, more: impl FnOnce(Agent, &std::path::Path) -> Agent) -> Rig {
            let dir = TempDir::new("service");
            let wg = Arc::new(wg);
            let agent = more(
                Agent::new(
                    wg.clone(),
                    Store::new(dir.path().join("state")),
                    secret(),
                    180,
                ),
                dir.path(),
            );
            Rig {
                agent,
                wg,
                counter: AtomicU64::new(0),
                dir,
            }
        }

        /// Has all three headers but a signature that is not valid.
        fn send_forged(&self) -> Reply {
            let time = NOW.to_string();
            let request = Request {
                method: "GET",
                path_and_query: "/v1/status",
                time: Some(&time),
                nonce: Some("forged-nonce-00000000"),
                signature: Some("00"),
                body: b"",
            };
            self.agent.handle(NOW, None, &request)
        }

        /// The stored list, read straight from the disk.
        fn stored(&self) -> Option<PeerList> {
            Store::new(self.dir.path().join("state")).load().unwrap()
        }

        fn put(&self, body: &[u8]) -> Reply {
            self.send("PUT", "/v1/peers", body)
        }

        fn send(&self, method: &str, path: &str, body: &[u8]) -> Reply {
            self.send_with_load(None, method, path, body)
        }

        fn send_with_load(
            &self,
            load1: Option<f64>,
            method: &str,
            path: &str,
            body: &[u8],
        ) -> Reply {
            let n = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
            let nonce = format!("test-nonce-{n:08}");
            let parts = Parts {
                method,
                path_and_query: path,
                time: NOW,
                nonce: &nonce,
                body,
            };
            let signature = sign(&secret(), &parts);
            let time = NOW.to_string();
            let request = Request {
                method,
                path_and_query: path,
                time: Some(&time),
                nonce: Some(&nonce),
                signature: Some(&signature),
                body,
            };
            self.agent.handle(NOW, load1, &request)
        }

        fn status(&self) -> Value {
            let reply = self.send("GET", "/v1/status", b"");
            assert_eq!(reply.status, 200, "{}", reply.body);
            serde_json::from_str(&reply.body).unwrap()
        }
    }

    #[test]
    fn a_slow_change_does_not_hold_up_refusals_or_status() {
        let wg = FakeWg::default();
        wg.set_delay(Duration::from_millis(1500));
        let rig = Rig::new(wg);

        std::thread::scope(|scope| {
            let slow_put = scope.spawn(|| rig.put(&peers_body(1, &[(K1, &["10.77.0.5/32"])])));
            // Let the PUT start and sit inside its slow `wg set`.
            std::thread::sleep(Duration::from_millis(300));

            let started = Instant::now();
            let refused = rig.send_forged();
            let status = rig.send("GET", "/v1/status", b"");
            let waited = started.elapsed();

            assert_eq!(refused, Reply::not_found());
            assert_eq!(status.status, 200, "{}", status.body);
            assert!(waited < Duration::from_millis(1000), "waited {waited:?}");
            assert_eq!(slow_put.join().unwrap().status, 200);
        });
    }

    /// Waits (up to 3 s) until `ready` is true.
    async fn eventually(what: &str, ready: impl Fn() -> bool) {
        for _ in 0..300 {
            if ready() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("gave up waiting for {what}");
    }

    #[tokio::test]
    async fn the_loop_repeats_and_a_failed_pass_does_not_stop_it() {
        let dir = TempDir::new("loop");
        let store = || Store::new(dir.path().join("state"));
        let list = PeerList {
            version: 1,
            peers: vec![bf_common::peers::PeerSpec {
                public_key: K1.to_string(),
                allowed_ips: vec!["10.77.0.5/32".to_string()],
                trackers: true,
            }],
        };
        store().save(&list).unwrap();
        let wg = Arc::new(FakeWg::with_peers(&[(K2, &["10.66.1.3/32"])]));
        let agent = Arc::new(Agent::new(wg.clone(), store(), secret(), 180));
        let task = tokio::spawn(keep_matching(agent, Duration::from_millis(20)));

        // The first pass: the stray goes, the listed peer comes.
        eventually("the first pass", || wg.has_peer(K1) && !wg.has_peer(K2)).await;

        // Drift behind the agent's back is put right by a later pass.
        wg.add_stray(K3, &["10.66.1.9/32"]);
        eventually("a later pass", || !wg.has_peer(K3)).await;

        // A pass that fails (WireGuard gone for a while) does not end the loop.
        wg.set_down(true);
        tokio::time::sleep(Duration::from_millis(100)).await;
        wg.add_stray(K4, &["10.66.1.10/32"]);
        wg.set_down(false);
        eventually("the pass after a failure", || !wg.has_peer(K4)).await;

        task.abort();
    }

    #[test]
    fn the_clock_is_read_while_the_verifier_lock_is_held() {
        let rig = Rig::new(FakeWg::default());
        let signed = Extra::signed("4444444444444444", "GET", "/v1/status");
        let time = NOW.to_string();
        let base = Request {
            method: "GET",
            path_and_query: "/v1/status",
            time: Some(&time),
            nonce: None,
            signature: None,
            body: b"",
        };
        let request = signed.request(&base);
        let locked_when_read = Cell::new(None);

        let reply = rig.agent.handle_with(
            || {
                if locked_when_read.get().is_none() {
                    locked_when_read.set(Some(rig.agent.verifier.try_lock().is_err()));
                }
                NOW
            },
            None,
            &request,
        );

        assert_eq!(reply.status, 200);
        assert_eq!(
            locked_when_read.get(),
            Some(true),
            "read the clock under the verifier lock"
        );
    }

    #[test]
    fn everything_but_a_valid_signed_request_for_a_real_path_gets_the_same_empty_404() {
        let rig = Rig::new(FakeWg::with_peers(&[(K1, &["10.66.1.2/32"])]));
        let good = Parts {
            method: "GET",
            path_and_query: "/v1/status",
            time: NOW,
            nonce: "0123456789abcdef",
            body: b"",
        };
        let good_signature = sign(&secret(), &good);
        let time = NOW.to_string();
        let signed = Request {
            method: "GET",
            path_and_query: "/v1/status",
            time: Some(&time),
            nonce: Some("0123456789abcdef"),
            signature: Some(&good_signature),
            body: b"",
        };
        // Correctly signed, but for something that is not a real route. Each has its own
        // nonce, because a correctly signed request uses its nonce up.
        let other_path = Extra::signed("1111111111111111", "GET", "/v1/nothing");
        let wrong_method = Extra::signed("2222222222222222", "POST", "/v1/status");
        let with_query = Extra::signed("3333333333333333", "GET", "/v1/status?x=1");

        let cases = [
            Request {
                time: None,
                nonce: None,
                signature: None,
                ..signed
            },
            Request {
                signature: Some("00"),
                ..signed
            },
            Request {
                time: Some("soon"),
                ..signed
            },
            other_path.request(&signed),
            wrong_method.request(&signed),
            with_query.request(&signed),
        ];
        for request in cases {
            assert_eq!(
                rig.agent.handle(NOW, None, &request),
                Reply::not_found(),
                "{request:?}"
            );
        }

        // The valid request itself works once, and a replay of it is the same 404.
        assert_eq!(rig.agent.handle(NOW, None, &signed).status, 200);
        assert_eq!(rig.agent.handle(NOW, None, &signed), Reply::not_found());
    }

    /// Fixed logins, or a failure.
    struct FakeLog(Result<Vec<bf_common::logins::Login>, String>);
    impl crate::logins::LoginLog for FakeLog {
        fn recent(&self, now: u64) -> Result<Vec<bf_common::logins::Login>, String> {
            assert_eq!(now, NOW, "asked as of the status's time");
            self.0.clone()
        }
    }

    const TEST_FP: &str = "SHA256:HvjXAIbzUdF23SQNP93/235ibkdyPOxPOROYgxD3Tjs";

    fn rig_with_log(log: Result<Vec<bf_common::logins::Login>, String>) -> Rig {
        Rig::new_with(FakeWg::default(), move |agent, _| {
            agent.with_login_log(Arc::new(FakeLog(log)))
        })
    }

    #[test]
    fn status_reports_recent_logins_named_from_authorized_keys() {
        let login = bf_common::logins::Login {
            at: NOW - 30,
            user: "root".to_string(),
            from: "203.0.113.7".parse().unwrap(),
            key: Some(TEST_FP.to_string()),
            key_name: Some("lao-test-key".to_string()),
        };
        let status = rig_with_log(Ok(vec![login])).status();
        assert_eq!(
            status["logins"],
            json!([{"at": NOW - 30, "user": "root", "from": "203.0.113.7", "key": TEST_FP, "key_name": "lao-test-key"}])
        );
    }

    /// No logins, and fixed attention news (or a failure).
    struct FakeAttention(Result<Option<bf_common::attention::Attention>, String>);
    impl crate::logins::LoginLog for FakeAttention {
        fn recent(&self, _now: u64) -> Result<Vec<bf_common::logins::Login>, String> {
            Ok(Vec::new())
        }
        fn attention(&self, now: u64) -> Result<Option<bf_common::attention::Attention>, String> {
            assert_eq!(now, NOW, "asked as of the status's time");
            self.0.clone()
        }
    }

    fn rig_with_attention(news: Result<Option<bf_common::attention::Attention>, String>) -> Rig {
        Rig::new_with(FakeWg::default(), move |agent, _| {
            agent.with_login_log(Arc::new(FakeAttention(news)))
        })
    }

    #[test]
    fn status_reports_what_needs_attention_and_nothing_when_it_cannot_say() {
        let news = bf_common::attention::Attention {
            reboot: true,
            reboot_by: vec!["linux-image-6.12.117+deb13-amd64".to_string()],
            waiting: vec![bf_common::attention::Waiting {
                name: "amneziawg-dkms".to_string(),
                version: "1.0.0-0~2026".to_string(),
            }],
        };
        let status = rig_with_attention(Ok(Some(news))).status();
        assert_eq!(
            status["attention"],
            json!({"reboot": true, "reboot_by": ["linux-image-6.12.117+deb13-amd64"],
                   "waiting": [{"name": "amneziawg-dkms", "version": "1.0.0-0~2026"}]})
        );
        for none in [
            Ok(None),
            Err("the attention file is 300 minutes old".to_string()),
        ] {
            let status = rig_with_attention(none).status();
            assert!(status.get("attention").is_none(), "{status}");
            assert!(status.get("peers").is_some(), "the rest is there");
        }
        assert!(
            Rig::new(FakeWg::default())
                .status()
                .get("attention")
                .is_none()
        );
    }

    #[test]
    fn without_a_login_log_or_when_it_fails_the_status_has_no_logins_but_still_answers() {
        assert!(Rig::new(FakeWg::default()).status().get("logins").is_none());
        let status = rig_with_log(Err("cannot read logins".to_string())).status();
        assert!(status.get("logins").is_none(), "{status}");
        assert!(status.get("peers").is_some(), "the rest is there");
    }

    #[test]
    fn status_reports_peers_with_masked_endpoints_and_never_a_secret() {
        let wg = FakeWg::with_peers(&[(K1, &["10.66.1.2/32"]), (K2, &["10.66.1.3/32"])]);
        wg.connect(K1, NOW - 12, "203.0.113.7:40000");
        let rig = Rig::new(wg);

        let reply = rig.send_with_load(Some(0.5), "GET", "/v1/status", b"");

        assert_eq!(reply.status, 200);
        let status: Value = serde_json::from_str(&reply.body).unwrap();
        assert_eq!(status["time"], json!(NOW));
        assert_eq!(status["online"], json!(1));
        assert_eq!(status["peers_total"], json!(2));
        assert_eq!(status["desired_version"], Value::Null);
        assert_eq!(status["load1"], json!(0.5));
        assert_eq!(status["peers"][0]["handshake_age"], json!(12));
        assert_eq!(status["peers"][0]["endpoint"], json!("203.0.113.0"));
        assert_eq!(status["peers"][1]["online"], json!(false));
        for secret in [PRIVATE_KEY, PRESHARED_KEY, "203.0.113.7"] {
            assert!(!reply.body.contains(secret), "{secret}");
        }
    }

    fn peers_body(version: u64, peers: &[(&str, &[&str])]) -> Vec<u8> {
        let peers: Vec<Value> = peers
            .iter()
            .map(|(key, ranges)| json!({ "public_key": key, "allowed_ips": ranges }))
            .collect();
        serde_json::to_vec(&json!({ "version": version, "peers": peers })).unwrap()
    }

    fn body_of(reply: &Reply) -> Value {
        serde_json::from_str(&reply.body).unwrap()
    }

    fn with_set(rig: Rig) -> (Rig, Arc<FakeSet>) {
        let set = Arc::new(FakeSet::default());
        let Rig {
            agent,
            wg,
            counter,
            dir,
        } = rig;
        let agent = agent.with_tracker_set(set.clone());
        (
            Rig {
                agent,
                wg,
                counter,
                dir,
            },
            set,
        )
    }

    /// A list where K2 and K4 have their trackers switch off; K4 also has an IPv6 range,
    /// which a set of IPv4 addresses cannot hold and so leaves out.
    fn list_with_switches(version: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({ "version": version, "peers": [
            { "public_key": K1, "allowed_ips": ["10.77.0.2/32"] },
            { "public_key": K2, "allowed_ips": ["10.77.0.3/32"], "trackers": false },
            { "public_key": K3, "allowed_ips": ["10.77.0.4/32"], "trackers": true },
            { "public_key": K4, "allowed_ips": ["fd00::5/128", "10.77.0.5/32"], "trackers": false },
        ] }))
        .unwrap()
    }

    #[test]
    fn the_set_holds_the_switched_off_addresses_after_a_list_and_again_on_every_pass() {
        let (rig, set) = with_set(Rig::new(FakeWg::default()));
        let off = vec![Ipv4Addr::new(10, 77, 0, 3), Ipv4Addr::new(10, 77, 0, 5)];

        assert_eq!(rig.put(&list_with_switches(1)).status, 200);
        assert_eq!(set.calls(), std::slice::from_ref(&off));

        rig.agent.reconcile().unwrap();
        assert_eq!(set.calls(), [off.clone(), off]);
    }

    #[test]
    fn a_failing_switch_changes_nothing_else_and_the_next_pass_tries_again() {
        let (rig, set) = with_set(Rig::new(FakeWg::default()));
        set.fail(true);

        let reply = rig.put(&list_with_switches(1));

        assert_eq!(reply.status, 200);
        assert_eq!(body_of(&reply)["added"], 4);
        assert_eq!(rig.wg.peers().len(), 4);
        set.fail(false);
        rig.agent.reconcile().unwrap();
        assert_eq!(set.calls().len(), 2);
    }

    #[test]
    fn without_a_switch_nothing_but_wireguard_is_touched() {
        let rig = Rig::new(FakeWg::default());
        assert_eq!(rig.put(&list_with_switches(1)).status, 200);
        rig.agent.reconcile().unwrap();
        assert_eq!(rig.wg.peers().len(), 4);
    }

    #[test]
    fn a_new_list_is_stored_then_applied_and_the_answer_says_what_changed() {
        let rig = Rig::new(FakeWg::with_peers(&[(K2, &["10.66.1.3/32"])]));

        let reply = rig.put(&peers_body(7, &[(K1, &["10.77.0.5/32"])]));

        assert_eq!(reply.status, 200, "{}", reply.body);
        assert_eq!(
            body_of(&reply),
            json!({ "version": 7, "added": 1, "removed": 1, "updated": 0 })
        );
        assert_eq!(
            rig.wg.peers(),
            [(K1.to_string(), vec!["10.77.0.5/32".to_string()])]
        );
        assert_eq!(rig.stored().unwrap().version, 7);
        assert_eq!(rig.status()["desired_version"], json!(7));
    }

    #[test]
    fn a_bad_list_a_stale_version_and_a_conflicting_retry_change_nothing() {
        let rig = Rig::new(FakeWg::with_peers(&[(K2, &["10.66.1.3/32"])]));
        let refused = [
            (b"{ nope".to_vec(), "bad_request"),
            (br#"{"version":1}"#.to_vec(), "bad_request"),
            (peers_body(1, &[("short", &["10.77.0.5/32"])]), "bad_list"),
            (peers_body(1, &[(K1, &["10.77.0.5/24"])]), "bad_list"),
        ];
        for (body, code) in refused {
            let reply = rig.put(&body);
            assert_eq!(reply.status, 400, "{code}: {}", reply.body);
            assert_eq!(body_of(&reply)["error"], json!(code));
        }
        let detail =
            body_of(&rig.put(&peers_body(1, &[("short", &["10.77.0.5/32"])])))["detail"].clone();
        assert_eq!(detail, json!("peers[0]: not a valid WireGuard key"));
        assert!(rig.wg.calls().is_empty());
        assert_eq!(rig.stored(), None);

        assert_eq!(
            rig.put(&peers_body(7, &[(K1, &["10.77.0.5/32"])])).status,
            200
        );
        let calls_so_far = rig.wg.calls().len();

        let older = rig.put(&peers_body(6, &[(K2, &["10.77.0.6/32"])]));
        assert_eq!(older.status, 409);
        assert_eq!(
            body_of(&older),
            json!({ "error": "stale", "stored_version": 7 })
        );
        let conflicting = rig.put(&peers_body(7, &[(K2, &["10.77.0.6/32"])]));
        assert_eq!(conflicting.status, 409);

        let retry = rig.put(&peers_body(7, &[(K1, &["10.77.0.5/32"])]));
        assert_eq!(retry.status, 200);
        assert_eq!(
            body_of(&retry),
            json!({ "version": 7, "added": 0, "removed": 0, "updated": 0 })
        );
        assert_eq!(rig.wg.calls().len(), calls_so_far);
        assert_eq!(rig.stored().unwrap().peers[0].public_key, K1);
    }

    #[test]
    fn an_empty_list_is_valid_and_removes_every_peer() {
        let rig = Rig::new(FakeWg::with_peers(&[
            (K1, &["10.66.1.2/32"]),
            (K2, &["10.66.1.3/32"]),
        ]));

        let reply = rig.put(&peers_body(1, &[]));

        assert_eq!(reply.status, 200, "{}", reply.body);
        assert_eq!(
            body_of(&reply),
            json!({ "version": 1, "added": 0, "removed": 2, "updated": 0 })
        );
        assert!(rig.wg.peers().is_empty());
    }

    #[test]
    fn a_list_that_cannot_be_applied_stays_stored_and_a_later_pass_finishes_it() {
        let wg = FakeWg::default();
        wg.set_changes_fail(true);
        let rig = Rig::new(wg);

        let reply = rig.put(&peers_body(7, &[(K1, &["10.77.0.5/32"])]));

        assert_eq!(reply.status, 503);
        assert_eq!(rig.stored().unwrap().version, 7);
        assert_eq!(rig.status()["desired_version"], json!(7));

        rig.wg.set_changes_fail(false);

        assert_eq!(
            rig.agent.reconcile().unwrap(),
            Some(Changes {
                added: 1,
                removed: 0,
                updated: 0
            })
        );
        assert_eq!(rig.wg.peers().len(), 1);
    }

    #[test]
    fn a_pass_forgets_idle_devices_only_once_there_is_a_list() {
        let wg = FakeWg::with_peers(&[(K1, &["10.77.0.5/32"])]);
        wg.connect(K1, NOW - 900, "203.0.113.7:51820");
        let rig = Rig::new(wg);
        assert_eq!(
            rig.agent.forget_idle(NOW).unwrap(),
            None,
            "no list: hands off"
        );
        assert_eq!(rig.agent.forget_idle(NOW + 30).unwrap(), None);
        assert!(rig.wg.calls().is_empty());

        assert_eq!(
            rig.put(&peers_body(1, &[(K1, &["10.77.0.5/32"])])).status,
            200
        );
        let before = rig.wg.calls().len();
        assert_eq!(
            rig.agent.forget_idle(NOW).unwrap(),
            Some(0),
            "first it looks"
        );
        assert_eq!(rig.agent.forget_idle(NOW + 30).unwrap(), Some(1));
        assert_eq!(
            rig.wg.calls()[before..],
            [format!("remove {K1}"), format!("set {K1} 10.77.0.5/32")]
        );
        assert_eq!(rig.agent.forget_idle(NOW + 60).unwrap(), Some(0));
    }

    #[test]
    fn a_device_whose_forgetting_broke_halfway_is_put_back_by_the_list_pass() {
        let wg = FakeWg::with_peers(&[(K1, &["10.77.0.5/32"])]);
        wg.connect(K1, NOW - 900, "203.0.113.7:51820");
        let rig = Rig::new(wg);
        assert_eq!(
            rig.put(&peers_body(1, &[(K1, &["10.77.0.5/32"])])).status,
            200
        );
        rig.agent.forget_idle(NOW).unwrap();
        rig.wg.set_sets_fail(true);
        assert!(rig.agent.forget_idle(NOW + 30).is_err());
        assert!(!rig.wg.has_peer(K1), "removed, and setting it again failed");
        rig.wg.set_sets_fail(false);
        assert_eq!(
            rig.agent.reconcile().unwrap(),
            Some(Changes {
                added: 1,
                removed: 0,
                updated: 0
            })
        );
        assert!(rig.wg.has_peer(K1));
    }

    #[test]
    fn with_no_list_a_pass_leaves_wireguard_alone() {
        let rig = Rig::new(FakeWg::with_peers(&[(K1, &["10.66.1.2/32"])]));

        assert_eq!(rig.agent.reconcile().unwrap(), None);

        assert!(rig.wg.calls().is_empty());
        assert_eq!(rig.wg.peers().len(), 1);
    }

    #[test]
    fn after_a_restart_the_stored_list_is_back_in_force_and_an_unusable_file_means_no_list() {
        let rig = Rig::new(FakeWg::default());
        assert_eq!(
            rig.put(&peers_body(7, &[(K1, &["10.77.0.5/32"])])).status,
            200
        );
        let state = rig.dir.path().join("state");

        // A new process over the same state, and an interface that forgot its peers.
        let wg = Arc::new(FakeWg::default());
        let restarted = Agent::new(wg.clone(), Store::new(state.clone()), secret(), 180);
        assert_eq!(
            restarted.reconcile().unwrap(),
            Some(Changes {
                added: 1,
                removed: 0,
                updated: 0
            })
        );
        assert_eq!(wg.peers().len(), 1);

        // A file that is not JSON, or a list that no longer passes the checks, is ignored.
        for unusable in [
            "{ not json",
            r#"{"version":9,"peers":[{"public_key":"x","allowed_ips":[]}]}"#,
        ] {
            std::fs::write(state.join("peers.json"), unusable).unwrap();
            let wg = Arc::new(FakeWg::with_peers(&[(K2, &["10.66.1.3/32"])]));
            let agent = Agent::new(wg.clone(), Store::new(state.clone()), secret(), 180);

            assert_eq!(agent.reconcile().unwrap(), None, "{unusable}");
            assert!(wg.calls().is_empty());
        }
    }

    /// Sends `agent` one correctly signed request, as it would arrive at `clock`.
    fn send_signed(agent: &Agent, clock: u64, time: u64, nonce: &str) -> Reply {
        let parts = Parts {
            method: "GET",
            path_and_query: "/v1/status",
            time,
            nonce,
            body: b"",
        };
        let signature = sign(&secret(), &parts);
        let time = time.to_string();
        agent.handle(
            clock,
            None,
            &Request {
                method: "GET",
                path_and_query: "/v1/status",
                time: Some(&time),
                nonce: Some(nonce),
                signature: Some(&signature),
                body: b"",
            },
        )
    }

    fn agent_over(state: &std::path::Path, started_at: u64) -> Agent {
        Agent::new_at(
            Arc::new(FakeWg::default()),
            Store::new(state.to_path_buf()),
            secret(),
            180,
            started_at,
        )
    }

    #[test]
    fn a_copy_of_a_request_accepted_before_a_restart_is_refused_after_it() {
        let dir = TempDir::new("replay-restart");
        let state = dir.path().join("state");
        let agent = agent_over(&state, NOW - 1_000);
        assert_eq!(
            send_signed(&agent, NOW, NOW, "nonce-before-restart-01").status,
            200
        );
        drop(agent);

        // A new process over the same state directory, five seconds later.
        let restarted = agent_over(&state, NOW + 5);
        let clock = NOW + 5;

        // The very bytes that were accepted before: refused, though still inside the window.
        let copy = send_signed(&restarted, clock, NOW, "nonce-before-restart-01");
        assert_eq!(copy, Reply::not_found());
        // So is anything else signed at or before the highest time the old process accepted,
        // which is the price of not having to remember the nonces.
        assert_eq!(
            send_signed(&restarted, clock, NOW - 3, "nonce-never-seen-before-1"),
            Reply::not_found()
        );
        assert_eq!(
            send_signed(&restarted, clock, NOW, "nonce-never-seen-before-2"),
            Reply::not_found()
        );
        // A request signed after the highest time works, and so does the next one.
        assert_eq!(
            send_signed(&restarted, clock, NOW + 1, "nonce-after-restart-01").status,
            200
        );
        assert_eq!(
            send_signed(&restarted, clock, NOW + 5, "nonce-after-restart-02").status,
            200
        );
    }

    #[test]
    fn the_mark_is_the_highest_time_accepted_and_only_verified_requests_move_it() {
        let dir = TempDir::new("replay-mark");
        let state = dir.path().join("state");
        let store = Store::new(state.clone());
        let agent = agent_over(&state, 0);
        assert_eq!(store.load_replay_mark(), Ok(None));

        assert_eq!(
            send_signed(&agent, NOW, NOW, "nonce-for-the-mark-01").status,
            200
        );
        assert_eq!(store.load_replay_mark(), Ok(Some(NOW)));

        // Older, but inside the window: served, and the mark stays.
        assert_eq!(
            send_signed(&agent, NOW, NOW - 10, "nonce-for-the-mark-02").status,
            200
        );
        assert_eq!(store.load_replay_mark(), Ok(Some(NOW)));

        // A forged signature, a replay and a time outside the window: refused, no change.
        let forged_time = (NOW + 30).to_string();
        let forged = Request {
            method: "GET",
            path_and_query: "/v1/status",
            time: Some(&forged_time),
            nonce: Some("nonce-for-the-mark-03"),
            signature: Some("00"),
            body: b"",
        };
        assert_eq!(agent.handle(NOW, None, &forged), Reply::not_found());
        assert_eq!(
            send_signed(&agent, NOW, NOW, "nonce-for-the-mark-01"),
            Reply::not_found()
        );
        assert_eq!(
            send_signed(&agent, NOW, NOW + 500, "nonce-for-the-mark-04"),
            Reply::not_found()
        );
        assert_eq!(store.load_replay_mark(), Ok(Some(NOW)));

        assert_eq!(
            send_signed(&agent, NOW, NOW + 20, "nonce-for-the-mark-05").status,
            200
        );
        assert_eq!(store.load_replay_mark(), Ok(Some(NOW + 20)));
    }

    #[test]
    fn with_no_mark_on_disk_the_start_time_is_the_floor() {
        let dir = TempDir::new("replay-first-start");
        let state = dir.path().join("state");
        let agent = agent_over(&state, NOW);

        // Requests signed in the second the agent started, or before it, might be copies of
        // ones an earlier build accepted, which kept no mark.
        assert_eq!(
            send_signed(&agent, NOW + 1, NOW, "nonce-at-the-start-0001"),
            Reply::not_found()
        );
        assert_eq!(
            send_signed(&agent, NOW + 1, NOW - 5, "nonce-at-the-start-0002"),
            Reply::not_found()
        );
        assert_eq!(
            send_signed(&agent, NOW + 1, NOW + 1, "nonce-at-the-start-0003").status,
            200
        );
    }

    #[test]
    fn a_damaged_mark_means_a_quiet_minute_and_not_no_protection() {
        let dir = TempDir::new("replay-damaged");
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("replay-mark"), "not a number").unwrap();
        let agent = agent_over(&state, NOW);

        // Nothing signed within a minute of the start can be told from an old copy.
        for (time, nonce) in [
            (NOW, "nonce-damaged-mark-01"),
            (NOW + 60, "nonce-damaged-mark-02"),
        ] {
            assert_eq!(
                send_signed(&agent, NOW + 60, time, nonce),
                Reply::not_found()
            );
        }
        assert_eq!(
            send_signed(&agent, NOW + 61, NOW + 61, "nonce-damaged-mark-03").status,
            200
        );
        // The next good request writes a mark again.
        assert_eq!(Store::new(state).load_replay_mark(), Ok(Some(NOW + 61)));
    }

    #[test]
    fn a_mark_that_cannot_be_written_is_logged_and_does_not_stop_the_agent_answering() {
        let dir = TempDir::new("replay-unwritable");
        // The state "directory" is a file, so nothing can be created under it.
        let state = dir.path().join("state");
        std::fs::write(&state, "in the way").unwrap();
        let agent = agent_over(&state, 0);

        assert_eq!(
            send_signed(&agent, NOW, NOW, "nonce-unwritable-mark-1").status,
            200
        );
        assert_eq!(
            send_signed(&agent, NOW, NOW + 1, "nonce-unwritable-mark-2").status,
            200
        );
    }

    #[test]
    fn when_wireguard_cannot_be_read_status_says_unavailable_and_not_zero_peers() {
        let wg = FakeWg::with_peers(&[(K1, &["10.66.1.2/32"])]);
        wg.set_down(true);
        let rig = Rig::new(wg);

        let reply = rig.send("GET", "/v1/status", b"");

        assert_eq!(reply.status, 503);
        assert_eq!(
            serde_json::from_str::<Value>(&reply.body).unwrap(),
            json!({ "error": "unavailable" })
        );
    }
}

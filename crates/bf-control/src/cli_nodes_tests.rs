//! Tests of `bf-control node ...` and `bf-control list raise`, included from `cli.rs`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bf_agent::testutil::NODE_PUBLIC_KEY;
use bf_common::peers::PeerList;

use super::*;
use crate::link::{FilesProblem, Link, NodeFiles};
use crate::nodes::Node;
use crate::testagent::{FakeConnector, FakeNode, T0, secret_hex};
use crate::testtls::Authority;

struct Env {
    db: PathBuf,
    nodes_dir: PathBuf,
    connector: FakeConnector,
    clock: Arc<std::sync::atomic::AtomicU64>,
}

fn env() -> Env {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "bf-clinodes-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("nodes")).unwrap();
    Env {
        db: dir.join("control.db"),
        nodes_dir: dir.join("nodes"),
        connector: FakeConnector::default(),
        clock: Arc::new(std::sync::atomic::AtomicU64::new(T0)),
    }
}

/// What a command printed: (exit code, stdout, stderr).
type Ran = (u8, String, String);

impl Env {
    fn run(&self, args: &[&str]) -> Ran {
        self.run_with_dir(Some(&self.nodes_dir), args)
    }

    fn run_with_dir(&self, nodes_dir: Option<&Path>, args: &[&str]) -> Ran {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let context = Context {
            key_file: None,
            nodes_dir,
            connector: &self.connector,
            password_input: None,
        };
        let code = run_in(&args, &self.db, &context, T0, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn write_files(&self, name: &str, secret_byte: u8) {
        use std::os::unix::fs::PermissionsExt;
        let secret = self.nodes_dir.join(format!("{name}.secret"));
        std::fs::write(&secret, secret_hex(secret_byte)).unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(
            self.nodes_dir.join(format!("{name}.pem")),
            Authority::root("Cli Test Root").pem(),
        )
        .unwrap();
    }

    /// Registers a node with its files and a fake agent.
    fn node(&self, name: &str, secret_byte: u8) -> Arc<FakeNode> {
        let (code, out, err) = self.run(&[
            "node",
            "add",
            name,
            "192.0.2.7:8443",
            "Toronto",
            "Canada",
            "--protocol",
            "wireguard",
        ]);
        assert_eq!(code, 0, "{out}{err}");
        self.write_files(name, secret_byte);
        let fake = FakeNode::new(self.clock.clone(), secret_byte, None);
        self.connector
            .nodes
            .lock()
            .unwrap()
            .insert(name.to_string(), fake.clone());
        fake
    }

    fn store(&self) -> Store {
        Store::open(&self.db).unwrap()
    }
}

fn never_shows_a_secret(env_output: &[&Ran], secrets: &[u8]) {
    for (_, out, err) in env_output {
        for byte in secrets {
            assert!(!out.contains(&secret_hex(*byte)) && !err.contains(&secret_hex(*byte)));
        }
    }
}

// ---- node add ----

#[test]
fn a_node_is_added_and_listed_and_the_files_it_still_needs_are_named() {
    let env = env();

    let (code, out, err) = env.run(&[
        "node",
        "add",
        "toronto",
        "192.0.2.7:8443",
        "Toronto",
        "Canada",
        "--protocol",
        "amneziawg",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("toronto"), "{out}");
    assert!(
        out.contains("toronto.secret") && out.contains("toronto.pem"),
        "{out}"
    );
    let node = env.store().node("toronto").unwrap().unwrap();
    assert_eq!(
        (node.title.as_str(), node.place.as_str()),
        ("Toronto", "Canada")
    );
    assert_eq!(node.created_at, T0);

    let (code, out, _) = env.run(&["node", "list"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("toronto") && out.contains("192.0.2.7:8443"),
        "{out}"
    );
    assert!(out.contains("enabled"), "{out}");
    assert!(out.contains("the secret file is missing"), "{out}");

    env.write_files("toronto", 0x11);
    let (_, out, _) = env.run(&["node", "list"]);
    assert!(out.contains("files ok"), "{out}");
    assert!(!out.contains("missing"), "{out}");
}

#[test]
fn a_node_that_breaks_a_rule_is_refused_with_the_rule_and_nothing_is_added() {
    let env = env();
    for (args, rule) in [
        (
            [
                "node",
                "add",
                "Toronto",
                "192.0.2.7:8443",
                "T",
                "C",
                "--protocol",
                "wireguard",
            ],
            "1 to 32 characters",
        ),
        (
            [
                "node",
                "add",
                "t",
                "toronto.example.com:8443",
                "T",
                "C",
                "--protocol",
                "wireguard",
            ],
            "IP address and a port",
        ),
        (
            [
                "node",
                "add",
                "t",
                "192.0.2.7:0",
                "T",
                "C",
                "--protocol",
                "wireguard",
            ],
            "IP address and a port",
        ),
        (
            [
                "node",
                "add",
                "t",
                "192.0.2.7:8443",
                "",
                "C",
                "--protocol",
                "wireguard",
            ],
            "1 to 40 characters",
        ),
        (
            [
                "node",
                "add",
                "t",
                "192.0.2.7:8443",
                "T",
                "a\nb",
                "--protocol",
                "wireguard",
            ],
            "1 to 40 characters",
        ),
    ] {
        let (code, out, err) = env.run(&args);
        assert_eq!(code, 1, "{args:?}: {out}{err}");
        assert!(err.contains(rule), "{args:?}: {err}");
    }
    assert!(env.store().nodes().unwrap().is_empty());

    env.node("toronto", 0x11);
    let (code, _, err) = env.run(&[
        "node",
        "add",
        "toronto",
        "198.51.100.1:8443",
        "T",
        "C",
        "--protocol",
        "amneziawg",
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("already registered"), "{err}");
    let (code, _, err) = env.run(&[
        "node",
        "add",
        "other",
        "192.0.2.7:8443",
        "T",
        "C",
        "--protocol",
        "wireguard",
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("already registered"), "{err}");
}

#[test]
fn commands_that_are_not_understood_print_the_usage_and_change_nothing() {
    let env = env();
    for args in [
        &["node"][..],
        &["node", "frobnicate"],
        &["node", "add", "toronto"],
        &["node", "add", "toronto", "192.0.2.7:8443", "T"],
        &[
            "node",
            "add",
            "toronto",
            "192.0.2.7:8443",
            "T",
            "C",
            "extra",
        ],
        &["node", "add", "-x", "192.0.2.7:8443", "T", "C"],
        &["node", "add", "toronto", "192.0.2.7:8443", "T", "C"],
        &[
            "node",
            "add",
            "toronto",
            "192.0.2.7:8443",
            "T",
            "C",
            "--protocol",
        ],
        &["node", "set-protocol", "toronto"],
        &["node", "set-protocol", "toronto", "wireguard", "x"],
        &["node", "set-location", "toronto"],
        &["node", "set-location", "toronto", "43.65,-79.38", "x"],
        &["node", "list", "extra"],
        &["node", "enable"],
        &["node", "remove", "a", "b"],
        &["node", "check"],
        &["list"],
        &["list", "raise"],
        &["list", "raise", "abc"],
        &["list", "raise", "-1"],
        &["list", "raise", "5", "6"],
        &["list", "show"],
    ] {
        let (code, _, err) = env.run(args);
        assert_eq!(code, 2, "{args:?}");
        assert!(
            err.contains("usage:") && err.contains("node add"),
            "{args:?}"
        );
    }
    assert!(env.store().nodes().unwrap().is_empty());
}

#[test]
fn an_empty_registry_says_so() {
    let env = env();
    let (code, out, _) = env.run(&["node", "list"]);
    assert_eq!(code, 0);
    assert!(out.contains("no nodes"), "{out}");
}

// ---- protocols (specs/dual-protocol.md) ----

#[test]
fn the_two_agents_of_one_server_are_added_with_their_protocols_and_listed_with_them() {
    let env = env();
    for (name, protocol) in [("toronto", "amneziawg"), ("toronto-wg", "wireguard")] {
        let (code, _, err) = env.run(&[
            "node",
            "add",
            name,
            "192.0.2.7:8443",
            "Toronto",
            "Canada",
            "--protocol",
            protocol,
        ]);
        assert_eq!(code, 0, "{name}: {err}");
    }
    let (code, _, err) = env.run(&[
        "node",
        "add",
        "toronto-wg2",
        "192.0.2.7:8443",
        "Toronto",
        "Canada",
        "--protocol",
        "wireguard",
    ]);
    assert_eq!(code, 1, "one WireGuard agent per address");
    assert!(err.contains("already registered"), "{err}");

    let (_, out, _) = env.run(&["node", "list"]);
    let line = |name: &str| {
        out.lines()
            .find(|l| l.starts_with(&format!("{name} ")))
            .unwrap_or_else(|| panic!("{name} in {out}"))
            .to_string()
    };
    assert!(line("toronto").contains("amneziawg"), "{out}");
    assert!(line("toronto-wg").contains("wireguard"), "{out}");
}

#[test]
fn a_protocol_must_be_one_of_the_two_words() {
    let env = env();
    for bad in ["WireGuard", "wg", "openvpn", ""] {
        let (code, _, err) = env.run(&[
            "node",
            "add",
            "toronto",
            "192.0.2.7:8443",
            "T",
            "C",
            "--protocol",
            bad,
        ]);
        assert_eq!(code, 1, "{bad:?}");
        assert!(err.contains("wireguard or amneziawg"), "{bad:?}: {err}");
    }
    assert!(env.store().nodes().unwrap().is_empty());
}

#[test]
fn an_older_node_is_listed_without_a_protocol_until_one_is_set() {
    let env = env();
    env.store()
        .add_node("toronto", "192.0.2.7:8443", "Toronto", "Canada", T0)
        .unwrap();
    let (_, out, _) = env.run(&["node", "list"]);
    assert!(out.contains("protocol not set"), "{out}");

    let (code, out, err) = env.run(&["node", "set-protocol", "toronto", "amneziawg"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("toronto") && out.contains("amneziawg"),
        "{out}"
    );
    assert_eq!(
        env.store().node("toronto").unwrap().unwrap().protocol,
        Some(crate::protocol::Protocol::AmneziaWg)
    );
    let (_, out, _) = env.run(&["node", "list"]);
    assert!(!out.contains("protocol not set"), "{out}");

    let (code, _, err) = env.run(&["node", "set-protocol", "toronto", "openvpn"]);
    assert_eq!(code, 1);
    assert!(err.contains("wireguard or amneziawg"), "{err}");
    let (code, _, err) = env.run(&["node", "set-protocol", "nowhere", "wireguard"]);
    assert_eq!(code, 1);
    assert!(err.contains("no node"), "{err}");
}

// ---- where each server is (decision 014) ----

#[test]
fn a_nodes_location_is_set_from_lat_comma_lon_and_listed() {
    let env = env();
    env.store()
        .add_node("toronto", "192.0.2.7:8443", "Toronto", "Canada", T0)
        .unwrap();
    let (_, out, _) = env.run(&["node", "list"]);
    assert!(out.contains("location not set"), "{out}");

    let (code, out, err) = env.run(&["node", "set-location", "toronto", "43.65,-79.38"]);

    assert_eq!(code, 0, "{err}");
    assert!(out.contains("toronto is at 43.65,-79.38"), "{out}");
    assert_eq!(
        env.store().node("toronto").unwrap().unwrap().location,
        Some(crate::closest::Location {
            lat: 43.65,
            lon: -79.38
        })
    );
    let (_, out, _) = env.run(&["node", "list"]);
    assert!(out.contains("at 43.65,-79.38"), "{out}");
    assert!(!out.contains("location not set"), "{out}");
}

#[test]
fn a_location_that_is_not_lat_comma_lon_or_a_name_nobody_has_is_refused() {
    let env = env();
    env.store()
        .add_node("toronto", "192.0.2.7:8443", "Toronto", "Canada", T0)
        .unwrap();
    for bad in [
        "43.65",
        "91,0",
        "0,181",
        "-79.38;43.65",
        "north,west",
        "NaN,0",
        "",
    ] {
        let (code, _, err) = env.run(&["node", "set-location", "toronto", bad]);
        assert_eq!(code, 1, "{bad:?}");
        assert!(err.contains("like 43.65,-79.38"), "{bad:?}: {err}");
    }
    assert_eq!(env.store().node("toronto").unwrap().unwrap().location, None);
    let (code, _, err) = env.run(&["node", "set-location", "nowhere", "43.65,-79.38"]);
    assert_eq!(code, 1);
    assert!(err.contains("no node"), "{err}");
}

// ---- enable, disable, remove ----

#[test]
fn a_node_is_disabled_enabled_and_removed_and_a_name_nobody_has_is_refused() {
    let env = env();
    env.node("toronto", 0x11);

    let (code, said, _) = env.run(&["node", "disable", "toronto"]);
    assert_eq!(code, 0);
    assert!(
        said.contains("being fixed"),
        "it says what the website will now show: {said}"
    );
    assert!(!env.store().node("toronto").unwrap().unwrap().enabled);
    let (_, out, _) = env.run(&["node", "list"]);
    assert!(out.contains("disabled"), "{out}");

    assert_eq!(env.run(&["node", "enable", "toronto"]).0, 0);
    assert!(env.store().node("toronto").unwrap().unwrap().enabled);

    assert_eq!(env.run(&["node", "remove", "toronto"]).0, 0);
    assert_eq!(env.store().node("toronto").unwrap(), None);
    assert!(
        env.nodes_dir.join("toronto.secret").exists(),
        "the files are left where they are"
    );

    for verb in ["enable", "disable", "remove", "check"] {
        let (code, _, err) = env.run(&["node", verb, "toronto"]);
        assert_eq!(code, 1, "{verb}");
        assert!(err.contains("no node"), "{verb}: {err}");
    }
}

// ---- node check ----

#[test]
fn a_check_asks_the_node_the_way_the_poller_does_and_prints_what_it_said() {
    let env = env();
    env.node("toronto", 0x11);

    let ran = env.run(&["node", "check", "toronto"]);

    let (code, out, err) = &ran;
    assert_eq!(*code, 0, "{err}");
    assert!(
        out.contains("toronto") && out.contains("192.0.2.7:8443"),
        "{out}"
    );
    assert!(
        out.contains(NODE_PUBLIC_KEY),
        "the server's public key: {out}"
    );
    assert!(out.contains("51820"), "{out}");
    assert!(out.contains("0 total, 0 online"), "{out}");
    assert!(out.contains("load: 0.1"), "{out}");
    assert!(
        out.contains("none yet") && out.contains("database is at version 1"),
        "the node has no list and the poller will send it: {out}"
    );
    never_shows_a_secret(&[&ran], &[0x11]);
}

#[test]
fn a_check_says_when_the_node_is_in_step_behind_or_ahead() {
    let env = env();
    let fake = env.node("toronto", 0x11);
    let mut store = env.store();
    let account = store.add_account("lao", 1).unwrap();
    let key = crate::keys::KeyPair::generate().unwrap().public_key;
    store.add_device(account.id, "d", &key, 1).unwrap();
    let database = store.publish(T0).unwrap();
    drop(store);

    // Send the node the database's list through a link of the same kind the poller makes.
    let files = crate::link::read_files(&env.nodes_dir, "toronto").unwrap();
    let node: Node = env.store().node("toronto").unwrap().unwrap();
    let link = env.connector_link(&node, &files);
    block(link.put_peers(T0 + 1, &database)).unwrap();
    assert!(fake.has(&key));

    let (code, out, err) = env.run(&["node", "check", "toronto"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("in step"), "{out}");
    assert!(out.contains("1 total"), "{out}");

    // A device the node has not been sent yet: the node is behind.
    let mut store = env.store();
    let second = crate::keys::KeyPair::generate().unwrap().public_key;
    store.add_device(1, "second", &second, 1).unwrap();
    drop(store);
    let (code, out, _) = env.run(&["node", "check", "toronto"]);
    assert_eq!(code, 0);
    assert!(out.contains("the poller will send it"), "{out}");
    assert!(!out.contains("in step"), "{out}");

    let ahead = PeerList {
        version: database.version + 4,
        peers: database.peers.clone(),
    };
    block(link.put_peers(T0 + 2, &ahead)).unwrap();
    let (code, out, _) = env.run(&["node", "check", "toronto"]);
    assert_eq!(code, 0);
    assert!(out.contains("AHEAD"), "{out}");
    assert!(
        out.contains(&format!("list raise {}", database.version + 4)),
        "it says what to run: {out}"
    );
}

#[test]
fn a_check_that_cannot_reach_the_node_says_why_and_fails() {
    let env = env();
    let fake = env.node("toronto", 0x11);
    fake.down.store(true, Ordering::SeqCst);

    let ran = env.run(&["node", "check", "toronto"]);

    assert_eq!(ran.0, 1);
    assert!(
        ran.2.contains("toronto") && ran.2.contains("cannot connect"),
        "{}",
        ran.2
    );
    assert!(
        ran.1.is_empty(),
        "nothing is printed as if it had worked: {}",
        ran.1
    );
    never_shows_a_secret(&[&ran], &[0x11]);

    fake.down.store(false, Ordering::SeqCst);
    env.write_files("toronto", 0x99);
    let (code, _, err) = env.run(&["node", "check", "toronto"]);
    assert_eq!(code, 1);
    assert!(err.contains("refused"), "a wrong secret: {err}");
}

#[test]
fn a_check_without_the_files_or_the_directory_says_what_is_missing() {
    let env = env();
    env.node("toronto", 0x11);
    std::fs::remove_file(env.nodes_dir.join("toronto.pem")).unwrap();

    let (code, _, err) = env.run(&["node", "check", "toronto"]);
    assert_eq!(code, 1);
    assert!(err.contains("root certificate file is missing"), "{err}");
    assert!(
        err.contains(env.nodes_dir.to_str().unwrap()),
        "it names the directory: {err}"
    );

    let (code, _, err) = env.run_with_dir(None, &["node", "check", "toronto"]);
    assert_eq!(code, 1);
    assert!(err.contains("BC_NODES_DIR"), "{err}");
}

// ---- list raise ----

#[test]
fn raising_the_version_makes_the_next_list_higher_and_says_what_it_did() {
    let env = env();
    let (_, out, _) = env.run(&["peers"]);
    assert!(out.contains("\"version\": 1"), "{out}");

    let (code, out, err) = env.run(&["list", "raise", "9"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("10"), "the next version: {out}");
    let (_, out, _) = env.run(&["peers"]);
    assert!(out.contains("\"version\": 10"), "{out}");

    let (code, out, _) = env.run(&["list", "raise", "5"]);
    assert_eq!(code, 0);
    assert!(out.contains("already") && out.contains("10"), "{out}");
    let (_, out, _) = env.run(&["peers"]);
    assert!(out.contains("\"version\": 10"), "unchanged: {out}");

    for bad in ["0", "1000000000001"] {
        let (code, _, err) = env.run(&["list", "raise", bad]);
        assert_eq!(code, 1, "{bad}");
        assert!(err.contains("whole number"), "{err}");
    }
}

// ---- helpers ----

fn block<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

impl Env {
    fn connector_link(&self, node: &Node, files: &NodeFiles) -> Link {
        let _: Option<FilesProblem> = None;
        let _ = Mutex::new(());
        self.connector.connect(node, files).unwrap()
    }
}

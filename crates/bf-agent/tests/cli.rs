//! Runs the real `bf-agent` binary against a fake `wg` script: the service starts, makes
//! WireGuard match the stored list, and `bf-agent probe` reads its status.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_bf-agent");
const SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
// Valid WireGuard keys: 32 bytes of 0x01 and of 0x02.
const K1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const K2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

struct Node {
    dir: PathBuf,
    port: u16,
    child: Option<Child>,
}

impl Node {
    fn new(label: &str) -> Node {
        let dir = std::env::temp_dir().join(format!("bf-agent-cli-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("state")).unwrap();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        std::fs::write(dir.join("agent.secret"), format!("{SECRET}\n")).unwrap();
        // A `wg` that logs what it is asked and shows one peer, K1, that is not on the list.
        let script = format!(
            "#!/bin/sh\necho \"$@\" >> '{log}'\nif [ \"$1\" = show ]; then\n  \
             printf 'PRIVATE\\tNODEPUBLIC\\t51820\\toff\\n'\n  \
             printf '{K1}\\tPSK\\t(none)\\t10.66.1.2/32\\t0\\t0\\t0\\toff\\n'\nfi\n",
            log = dir.join("wg.log").display()
        );
        let wg = dir.join("fake-wg");
        std::fs::write(&wg, script).unwrap();
        std::process::Command::new("chmod")
            .arg("755")
            .arg(&wg)
            .status()
            .unwrap();
        Node {
            dir,
            port,
            child: None,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(BIN);
        command
            .env("BF_LISTEN", format!("127.0.0.1:{}", self.port))
            .env("BF_SECRET_FILE", self.dir.join("agent.secret"))
            .env("BF_STATE_DIR", self.dir.join("state"))
            .env("BF_WG_BIN", self.dir.join("fake-wg"))
            .stdin(Stdio::null());
        command
    }

    fn start(&mut self) {
        let log = std::fs::File::create(self.dir.join("agent.log")).unwrap();
        self.child = Some(
            self.command()
                .stdout(Stdio::null())
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        );
    }

    /// Everything the agent wrote to its standard error.
    fn agent_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("agent.log")).unwrap_or_default()
    }

    fn wg_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("wg.log")).unwrap_or_default()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(Instant::now() < deadline, "gave up waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn path_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn the_service_starts_matches_the_stored_list_and_probe_reads_its_status() {
    let mut node = Node::new("serve");
    let list = format!(
        r#"{{"version":4,"peers":[{{"public_key":"{K2}","allowed_ips":["10.77.0.9/32"]}}]}}"#
    );
    std::fs::write(node.dir.join("state").join("peers.json"), list).unwrap();

    node.start();

    // The first pass on start removes the peer that is not on the list and adds the one that is.
    wait_until("the first pass", || {
        node.wg_log()
            .contains(&format!("set wg0 peer {K2} allowed-ips 10.77.0.9/32"))
    });
    assert!(
        node.wg_log().contains(&format!("set wg0 peer {K1} remove")),
        "{}",
        node.wg_log()
    );

    let mut answer = None;
    wait_until("probe to be answered", || {
        let output = node.command().arg("probe").output().unwrap();
        if output.status.success() {
            answer = Some(String::from_utf8(output.stdout).unwrap());
        }
        answer.is_some()
    });
    let status: serde_json::Value = serde_json::from_str(&answer.unwrap()).unwrap();
    assert_eq!(status["desired_version"], 4, "{status}");
    assert_eq!(status["interface"]["listen_port"], 51820);
    assert_eq!(status["peers_total"], 1);

    // What the agent wrote to stderr: that it is listening and what it changed, and none of
    // the secrets the fake wg printed in its dump, nor the signing secret.
    wait_until("the reconcile line in the log", || {
        node.agent_log()
            .contains("reconcile: added 1, removed 1, updated 0")
    });
    let log = node.agent_log();
    assert!(log.contains("listening on"), "{log}");
    for secret in ["PRIVATE", "PSK", SECRET] {
        assert!(!log.contains(secret), "the log holds {secret}: {log}");
    }
}

#[test]
fn with_the_tracker_switch_on_the_first_pass_fills_this_interfaces_set() {
    let mut node = Node::new("trackers");
    let list = format!(
        r#"{{"version":2,"peers":[
            {{"public_key":"{K1}","allowed_ips":["10.77.0.2/32"]}},
            {{"public_key":"{K2}","allowed_ips":["10.77.0.9/32"],"trackers":false}}]}}"#
    );
    std::fs::write(node.dir.join("state").join("peers.json"), list).unwrap();
    // A fake `nft` that keeps what it was told.
    let nft = node.dir.join("fake-nft");
    std::fs::write(
        &nft,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{args}'\ncat >> '{input}'\n",
            args = node.dir.join("nft.args").display(),
            input = node.dir.join("nft.input").display()
        ),
    )
    .unwrap();
    Command::new("chmod").arg("755").arg(&nft).status().unwrap();

    let log = std::fs::File::create(node.dir.join("agent.log")).unwrap();
    node.child = Some(
        node.command()
            .env("BF_TRACKERS", "nft")
            .env("BF_NFT_BIN", &nft)
            .env("BF_INTERFACE", "awg0")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );

    let input = || std::fs::read_to_string(node.dir.join("nft.input")).unwrap_or_default();
    wait_until("the switch to be filled", || !input().is_empty());
    assert!(
        input().starts_with(
            "flush set inet barely_free_dns off_awg0\n\
             add element inet barely_free_dns off_awg0 { 10.77.0.9 }\n"
        ),
        "{}",
        input()
    );
    let args = std::fs::read_to_string(node.dir.join("nft.args")).unwrap();
    assert!(args.starts_with("-f -\n"), "{args}");
}

#[test]
fn probe_fails_when_nothing_is_listening_and_unknown_arguments_are_refused() {
    let node = Node::new("probe");

    let probe = node.command().arg("probe").output().unwrap();
    assert!(!probe.status.success());

    let unknown = node.command().arg("frobnicate").output().unwrap();
    assert_eq!(unknown.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("usage"),
        "{}",
        path_str(&node.dir)
    );
}

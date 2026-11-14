//! Runs the real `bf-control` program, to prove `main` hands the command line to the
//! admin commands and keeps serving the website when there are no arguments.

use std::path::PathBuf;
use std::process::{Command, Output};

fn temp_db(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bf-control-bin-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("control.db")
}

fn run(db: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bf-control"))
        .args(args)
        .env("BC_DB", db)
        .env_remove("BC_LISTEN")
        .output()
        .expect("the program starts")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn the_program_runs_admin_commands_against_the_database_named_by_bc_db() {
    let db = temp_db("admin");

    let made = run(&db, &["account", "add", "lao"]);
    assert_eq!(made.status.code(), Some(0), "{}", text(&made.stderr));
    assert!(text(&made.stdout).contains("account 1"));

    let device = run(&db, &["device", "add", "1", "phone"]);
    assert_eq!(device.status.code(), Some(0), "{}", text(&device.stderr));
    let shown = text(&device.stdout);
    assert!(shown.contains("private key:"), "{shown}");
    assert!(
        !text(&device.stderr).contains("private key"),
        "the key goes to stdout only"
    );

    let listed = run(&db, &["account", "list"]);
    assert_eq!(listed.status.code(), Some(0));
    assert!(text(&listed.stdout).contains("1 of 3 devices"));

    let history = run(&db, &["kick", "list"]);
    assert_eq!(history.status.code(), Some(0));
    assert!(text(&history.stdout).contains("no kicks"));

    let peers = run(&db, &["peers"]);
    assert_eq!(peers.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&peers.stdout).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["peers"].as_array().unwrap().len(), 1);
}

#[test]
fn a_command_that_is_not_understood_exits_2_with_the_usage_on_stderr() {
    let db = temp_db("usage");

    let out = run(&db, &["kick", "1"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("usage:"));
    assert!(out.stdout.is_empty());
}

#[test]
fn a_refused_command_exits_1_and_says_why() {
    let db = temp_db("refused");

    let out = run(&db, &["device", "add", "5", "phone"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no account with that id"));
}

#[test]
fn with_no_arguments_it_still_serves_the_website_and_refuses_a_public_address() {
    let db = temp_db("serve");

    // `BC_LISTEN` off localhost is refused at once, which shows the no-argument path
    // is the website and not the admin tool, without leaving a server running.
    let out = Command::new(env!("CARGO_BIN_EXE_bf-control"))
        .env("BC_DB", &db)
        .env("BC_LISTEN", "0.0.0.0:18500")
        .output()
        .expect("the program starts");
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("BC_LISTEN must be on localhost"));
    assert!(
        !db.exists(),
        "serving the website does not touch the database"
    );
}

#[cfg(unix)]
#[test]
fn a_setting_that_is_not_text_is_refused_and_never_falls_back_to_the_default() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let not_text = OsString::from_vec(b"/tmp/\xff.db".to_vec());

    let admin = Command::new(env!("CARGO_BIN_EXE_bf-control"))
        .args(["account", "list"])
        .env("BC_DB", &not_text)
        .output()
        .expect("the program starts");
    assert_eq!(admin.status.code(), Some(1));
    assert!(text(&admin.stderr).contains("BC_DB must be text"));

    let site = Command::new(env!("CARGO_BIN_EXE_bf-control"))
        .env("BC_LISTEN", &not_text)
        .output()
        .expect("the program starts");
    assert_eq!(site.status.code(), Some(1));
    assert!(text(&site.stderr).contains("BC_LISTEN must be text"));
}

// ---- the real server, started for real ----

mod server {
    use std::io::{BufRead, Read, Write};
    use std::net::TcpStream;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    pub fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    pub struct Running {
        child: Child,
        pub port: u16,
        log: Arc<Mutex<String>>,
        reader: std::thread::JoinHandle<()>,
    }

    impl Running {
        /// Starts the program with no arguments (so: the website) and waits until it says it
        /// is serving on its port. A free port can be taken by another test's server before
        /// this one binds it, and then something else would answer there: so the program's
        /// own line is what counts, and a program that could not bind gets another port.
        pub fn start(envs: &[(&str, String)]) -> Running {
            for _ in 0..5 {
                let port = free_port();
                let mut command = Command::new(env!("CARGO_BIN_EXE_bf-control"));
                command
                    .env_clear()
                    .env("BC_LISTEN", format!("127.0.0.1:{port}"))
                    .stderr(Stdio::piped())
                    .stdout(Stdio::null());
                for (name, value) in envs {
                    command.env(name, value);
                }
                let mut child = command.spawn().expect("the program starts");
                let stderr = child.stderr.take().unwrap();
                let log = Arc::new(Mutex::new(String::new()));
                let sink = log.clone();
                let reader = std::thread::spawn(move || {
                    let mut stderr = std::io::BufReader::new(stderr);
                    let mut line = String::new();
                    while matches!(stderr.read_line(&mut line), Ok(n) if n > 0) {
                        sink.lock().unwrap().push_str(&line);
                        line.clear();
                    }
                });
                let ready = format!("serving the website on 127.0.0.1:{port}");
                let started = Instant::now();
                loop {
                    if log.lock().unwrap().contains(&ready) {
                        return Running {
                            child,
                            port,
                            log,
                            reader,
                        };
                    }
                    if let Ok(Some(_)) = child.try_wait() {
                        break;
                    }
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "it did not start: {}",
                        log.lock().unwrap()
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
                let _ = reader.join();
            }
            panic!("it did not start on any of five ports");
        }

        /// A bare GET: the status code and the whole answer.
        pub fn get(&self, path: &str) -> (u16, String) {
            let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
            write!(
                stream,
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).unwrap();
            let status = answer.split(' ').nth(1).unwrap().parse().unwrap();
            (status, answer)
        }

        /// Stops it and returns what it wrote to standard error.
        pub fn stop(mut self) -> String {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = self.reader.join();
            self.log.lock().unwrap().clone()
        }
    }
}

#[cfg(unix)]
fn private_file(path: &std::path::Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
#[test]
fn the_website_starts_with_sign_in_off_when_it_is_not_set_up_and_says_why() {
    let dir = std::env::temp_dir().join(format!("bf-control-bin-{}-off", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("control.db");

    let running = server::Running::start(&[
        ("BC_KEY_FILE", dir.join("control.key").display().to_string()),
        ("BC_DB", db.display().to_string()),
    ]);
    let (front, _) = running.get("/");
    let (signin, _) = running.get("/signin");
    let log = running.stop();

    assert_eq!(front, 200, "the site is up");
    assert_eq!(signin, 404, "and sign-in is not there");
    assert!(log.contains("sign-in is off"), "{log}");
    assert!(log.contains("key file"), "it says what is missing: {log}");
    assert!(!db.exists(), "no database is made when sign-in is off");
    assert!(!dir.join("control.key").exists(), "and no key file is made");
}

#[cfg(unix)]
#[test]
fn the_website_starts_with_sign_in_on_when_everything_is_in_place() {
    let dir = std::env::temp_dir().join(format!("bf-control-bin-{}-on", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("control.key");
    bf_control::secrets::ControlKeys::load_or_create(&key).unwrap();
    let resend = dir.join("resend.key");
    private_file(&resend, "re_SECRETKEY_for_this_test\n");
    let db = dir.join("control.db");
    let port_for_origin = server::free_port();

    let running = server::Running::start(&[
        ("BC_KEY_FILE", key.display().to_string()),
        ("BC_RESEND_KEY_FILE", resend.display().to_string()),
        ("BC_DB", db.display().to_string()),
        ("BC_ORIGINS", format!("http://127.0.0.1:{port_for_origin}")),
    ]);
    let (front, _) = running.get("/");
    let (signin, page) = running.get("/signin");
    let log = running.stop();

    assert_eq!(front, 200);
    assert_eq!(signin, 200);
    assert!(
        page.contains("form-action 'self'"),
        "the sign-in page has its own policy"
    );
    assert!(log.contains("sign-in pages are on"), "{log}");
    assert!(db.exists(), "the database was opened");
    assert!(!log.contains("SECRETKEY"), "the key is never logged: {log}");
}

/// A directory with the key files sign-in needs, and the settings that point at them.
#[cfg(unix)]
fn sign_in_settings(name: &str) -> (std::path::PathBuf, Vec<(&'static str, String)>) {
    let dir = std::env::temp_dir().join(format!("bf-control-bin-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("control.key");
    bf_control::secrets::ControlKeys::load_or_create(&key).unwrap();
    let resend = dir.join("resend.key");
    private_file(&resend, "re_SECRETKEY_for_this_test\n");
    let port_for_origin = server::free_port();
    let settings = vec![
        ("BC_KEY_FILE", key.display().to_string()),
        ("BC_RESEND_KEY_FILE", resend.display().to_string()),
        ("BC_DB", dir.join("control.db").display().to_string()),
        ("BC_ORIGINS", format!("http://127.0.0.1:{port_for_origin}")),
    ];
    (dir, settings)
}

#[cfg(unix)]
#[test]
fn sign_up_is_closed_unless_it_is_switched_on() {
    let (_dir, settings) = sign_in_settings("closed-default");

    let running = server::Running::start(&settings);
    let (_, front) = running.get("/");
    let (_, signin) = running.get("/signin");
    let log = running.stop();

    assert!(front.contains("Closed beta"), "{front}");
    assert!(signin.contains("only accounts we have made"), "{signin}");
    assert!(!log.contains("sign-up is open"), "{log}");
}

#[cfg(unix)]
#[test]
fn bc_open_sign_up_equals_one_opens_the_doors_and_says_so_in_the_log() {
    let (_dir, mut settings) = sign_in_settings("open");
    settings.push(("BC_OPEN_SIGNUP", "1".to_string()));

    let running = server::Running::start(&settings);
    let (front_status, front) = running.get("/");
    let (signin_status, signin) = running.get("/signin");
    let log = running.stop();

    assert_eq!((front_status, signin_status), (200, 200));
    assert!(!front.contains("Closed beta"), "{front}");
    assert!(front.contains("sign-up is open"), "{front}");
    assert!(signin.contains("create an account"), "{signin}");
    assert!(log.contains("sign-up is open"), "{log}");
    assert!(!log.contains("SECRETKEY"), "{log}");
}

#[cfg(unix)]
#[test]
fn a_bc_open_sign_up_that_is_not_zero_or_one_keeps_sign_in_off_and_says_why() {
    let (dir, mut settings) = sign_in_settings("open-typo");
    settings.push(("BC_OPEN_SIGNUP", "yes".to_string()));

    let running = server::Running::start(&settings);
    let (front_status, _) = running.get("/");
    let (signin_status, _) = running.get("/signin");
    let log = running.stop();

    assert_eq!(front_status, 200, "the site is up");
    assert_eq!(signin_status, 404, "and nothing is opened by a typo");
    assert!(log.contains("sign-in is off"), "{log}");
    assert!(log.contains("BC_OPEN_SIGNUP"), "{log}");
    assert!(!dir.join("control.db").exists(), "no database was made");
}

#[cfg(unix)]
#[test]
fn a_busy_setting_that_cannot_be_read_keeps_sign_in_off_and_says_why() {
    for (name, value) in [("BC_NODE_BUSY_ONLINE", "lots"), ("BC_NODE_BUSY_LOAD", "0")] {
        let (dir, mut settings) = sign_in_settings(&format!("busy-{value}"));
        settings.push((name, value.to_string()));

        let running = server::Running::start(&settings);
        let (front_status, _) = running.get("/");
        let (signin_status, _) = running.get("/signin");
        let log = running.stop();

        assert_eq!(front_status, 200, "{name}: the site is up");
        assert_eq!(signin_status, 404, "{name}");
        assert!(log.contains("sign-in is off"), "{name}: {log}");
        assert!(log.contains(name), "{name}: {log}");
        assert!(!dir.join("control.db").exists(), "{name}: no database");
    }
    let (_dir, mut settings) = sign_in_settings("busy-good");
    settings.push(("BC_NODE_BUSY_ONLINE", "25".to_string()));
    settings.push(("BC_NODE_BUSY_LOAD", "1.5".to_string()));
    let running = server::Running::start(&settings);
    let (signin_status, _) = running.get("/signin");
    running.stop();
    assert_eq!(signin_status, 200, "good values are taken");
}

#[cfg(unix)]
#[test]
fn a_half_set_up_sign_in_stays_off_and_makes_nothing() {
    let dir = std::env::temp_dir().join(format!("bf-control-bin-{}-half", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("control.key");
    bf_control::secrets::ControlKeys::load_or_create(&key).unwrap();
    let db = dir.join("control.db");

    let running = server::Running::start(&[
        ("BC_KEY_FILE", key.display().to_string()),
        (
            "BC_RESEND_KEY_FILE",
            dir.join("resend.key").display().to_string(),
        ),
        ("BC_DB", db.display().to_string()),
    ]);
    let (signin, _) = running.get("/signin");
    let log = running.stop();

    assert_eq!(signin, 404);
    assert!(
        log.contains("sign-in is off") && log.contains("Resend"),
        "{log}"
    );
    assert!(!db.exists());
}

#[test]
fn a_bad_origins_setting_keeps_sign_in_off_with_the_reason() {
    let dir = std::env::temp_dir().join(format!("bf-control-bin-{}-origins", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let running = server::Running::start(&[
        ("BC_KEY_FILE", dir.join("control.key").display().to_string()),
        ("BC_ORIGINS", "barely-free.com/".to_string()),
    ]);
    let log = running.stop();

    assert!(log.contains("sign-in is off"), "{log}");
    assert!(log.contains("barely-free.com/"), "{log}");
}

// ---- the node poller, started for real ----

#[path = "support/tls.rs"]
mod tls;

mod poller_flow {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use bf_agent::service::{Agent, Request};
    use bf_agent::testutil::{FakeWg, NODE_PUBLIC_KEY, TempDir};
    use bf_common::sign::unhex;

    use super::{private_file, server, text, tls};

    const SECRET: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("bf-control-poll-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("nodes")).unwrap();
        dir
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Runs an admin command with the node settings pointed at `dir`.
    fn admin(dir: &Path, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_bf-control"))
            .args(args)
            .env("BC_DB", dir.join("control.db"))
            .env("BC_NODES_DIR", dir.join("nodes"))
            .env("BC_KEY_FILE", dir.join("control.key"))
            .env_remove("BC_LISTEN")
            .output()
            .expect("the program starts")
    }

    /// The real agent behind a TLS server, as a node is behind Caddy.
    struct FakeNode {
        server: tls::Server,
        wg: Arc<FakeWg>,
        root_pem: String,
        _state: TempDir,
    }

    fn fake_node() -> FakeNode {
        let root = tls::Authority::root("Binary Test Root");
        let intermediate = root.intermediate("Binary Test Intermediate");
        let wg = Arc::new(FakeWg::default());
        let state = TempDir::new("binary-agent");
        let agent = Arc::new(Agent::new_at(
            wg.clone(),
            bf_agent::store::Store::new(state.path().to_path_buf()),
            unhex(SECRET).unwrap(),
            180,
            now() - 1_000,
        ));
        let handler: tls::Handler = Arc::new(move |request| {
            let reply = agent.handle(
                now(),
                Some(0.1),
                &Request {
                    method: &request.method,
                    path_and_query: &request.path,
                    time: request.header("x-bf-time"),
                    nonce: request.header("x-bf-nonce"),
                    signature: request.header("x-bf-sig"),
                    body: &request.body,
                },
            );
            tls::Response::new(reply.status, reply.body)
        });
        let server = tls::Server::tls(
            intermediate.leaf(&["toronto.agent.internal"], false),
            handler,
        );
        FakeNode {
            server,
            wg,
            root_pem: root.pem(),
            _state: state,
        }
    }

    fn register(dir: &Path, node: &FakeNode) {
        let address = node.server.addr.to_string();
        let added = admin(
            dir,
            &[
                "node",
                "add",
                "toronto",
                &address,
                "Toronto",
                "Canada",
                "--protocol",
                "amneziawg",
            ],
        );
        assert_eq!(added.status.code(), Some(0), "{}", text(&added.stderr));
        private_file(&dir.join("nodes/toronto.secret"), SECRET);
        std::fs::write(dir.join("nodes/toronto.pem"), &node.root_pem).unwrap();
    }

    fn wait_until(what: &str, seconds: u64, mut ok: impl FnMut() -> bool) {
        let started = Instant::now();
        while !ok() {
            assert!(
                started.elapsed() < Duration::from_secs(seconds),
                "timed out waiting for {what}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn the_real_program_checks_a_node_over_pinned_tls_then_polls_it_and_shows_it_on_the_front_page()
    {
        let dir = dir("flow");
        let node = fake_node();
        register(&dir, &node);
        assert_eq!(
            admin(&dir, &["account", "add", "lao"]).status.code(),
            Some(0)
        );
        let device = admin(&dir, &["device", "add", "1", "phone"]);
        assert_eq!(device.status.code(), Some(0), "{}", text(&device.stderr));
        let shown = text(&device.stdout);
        let key = shown
            .lines()
            .find_map(|line| line.strip_prefix("public key:"))
            .unwrap()
            .trim()
            .to_string();

        // The check goes through the real HTTPS connector and the pinned root.
        let check = admin(&dir, &["node", "check", "toronto"]);
        let printed = text(&check.stdout);
        assert_eq!(
            check.status.code(),
            Some(0),
            "{}{}",
            printed,
            text(&check.stderr)
        );
        assert!(
            printed.contains("answered") && printed.contains(NODE_PUBLIC_KEY),
            "{printed}"
        );
        assert!(!printed.contains(SECRET) && !text(&check.stderr).contains(SECRET));

        let running = server::Running::start(&[
            ("BC_DB", dir.join("control.db").display().to_string()),
            ("BC_NODES_DIR", dir.join("nodes").display().to_string()),
            ("BC_POLL_SECS", "2".to_string()),
        ]);
        wait_until("the card to say Up", 20, || {
            running
                .get("/")
                .1
                .contains("<span class=\"state up\">Up</span>")
        });
        let (status, front) = running.get("/");
        assert_eq!(status, 200);
        assert!(
            front.contains("<strong>Toronto</strong>") && front.contains("Canada"),
            "{front}"
        );
        assert!(
            !front.contains("Dallas"),
            "only the registered node is shown"
        );
        assert!(
            node.wg.has_peer(&key),
            "the device reached the node's WireGuard"
        );

        // The status page says the same, and gives words only.
        let (status, page) = running.get("/status");
        assert_eq!(status, 200);
        assert!(
            page.contains("<strong>Toronto</strong><span class=\"where\">Canada</span><span class=\"where\">10% load</span><span class=\"state up\">Up</span>"),
            "{page}"
        );
        assert!(!page.contains("toronto") && !page.contains(&key), "{page}");

        // Disabling the node (what an admin does to repair it) turns it to "Being fixed" on
        // both pages without stopping the site; enabling it brings it back.
        let off = admin(&dir, &["node", "disable", "toronto"]);
        assert_eq!(off.status.code(), Some(0), "{}", text(&off.stderr));
        wait_until("/status to say Being fixed", 20, || {
            running
                .get("/status")
                .1
                .contains("<span class=\"state\">Being fixed</span>")
        });
        assert!(
            running
                .get("/")
                .1
                .contains("<strong>Toronto</strong><span class=\"where\">Canada</span><span class=\"state\">Being fixed</span>"),
            "the front page card too"
        );
        assert_eq!(running.get("/healthz").0, 200);
        let on = admin(&dir, &["node", "enable", "toronto"]);
        assert_eq!(on.status.code(), Some(0), "{}", text(&on.stderr));
        wait_until("/status to say Up again", 20, || {
            running
                .get("/status")
                .1
                .contains("<span class=\"state up\">Up</span>")
        });

        // A device made afterwards arrives within a few passes.
        let second = admin(&dir, &["device", "add", "1", "laptop"]);
        let second_key = text(&second.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("public key:"))
            .unwrap()
            .trim()
            .to_string();
        wait_until("the second device to reach the node", 20, || {
            node.wg.has_peer(&second_key)
        });

        let log = running.stop();
        assert!(log.contains("the node poller is on"), "{log}");
        assert!(
            log.contains("alerts are off: there is no address file at /etc/barely-free/alert-to"),
            "{log}"
        );
        assert!(log.contains("node toronto: online"), "{log}");
        assert!(log.contains("list version 1 sent"), "{log}");
        assert!(
            !log.contains(SECRET) && !log.contains(&key),
            "no secret or key in the log: {log}"
        );
    }

    #[test]
    fn both_pages_call_a_server_overloaded_by_the_busy_settings_the_program_was_given() {
        let dir = dir("busy");
        let node = fake_node();
        register(&dir, &node);
        // The fake agent reports a load of 0.1; a limit of 0.05 makes it busy.
        let running = server::Running::start(&[
            ("BC_DB", dir.join("control.db").display().to_string()),
            ("BC_NODES_DIR", dir.join("nodes").display().to_string()),
            ("BC_POLL_SECS", "2".to_string()),
            ("BC_NODE_BUSY_LOAD", "0.05".to_string()),
        ]);
        wait_until("/status to say Overloaded", 20, || {
            running
                .get("/status")
                .1
                .contains("<span class=\"state\">Overloaded</span>")
        });
        assert!(
            running.get("/").1.contains(
                "<strong>Toronto</strong><span class=\"where\">Canada</span><span class=\"state\">Overloaded</span>"
            ),
            "the front page agrees"
        );
        running.stop();
    }

    #[test]
    fn the_status_page_shows_the_uptime_the_real_poller_recorded_and_a_note_from_node_disable() {
        let dir = dir("history");
        let node = fake_node();
        register(&dir, &node);
        let running = server::Running::start(&[
            ("BC_DB", dir.join("control.db").display().to_string()),
            ("BC_NODES_DIR", dir.join("nodes").display().to_string()),
            ("BC_POLL_SECS", "2".to_string()),
        ]);
        // The poller counts each pass in the database and puts the summary on the page.
        wait_until("the uptime list to show a percentage", 20, || {
            running
                .get("/status")
                .1
                .contains("<li><strong>Toronto</strong>: 100.0% over 1 day</li>")
        });

        // A note set with the admin command shows under a server that is being fixed.
        let off = admin(
            &dir,
            &[
                "node",
                "disable",
                "toronto",
                "--note",
                "back at 20:00 & <soon>",
            ],
        );
        assert_eq!(off.status.code(), Some(0), "{}", text(&off.stderr));
        wait_until("the note to show", 20, || {
            running
                .get("/status")
                .1
                .contains("<p class=\"note\">Toronto: back at 20:00 &amp; &lt;soon&gt;</p>")
        });
        let (_, page) = running.get("/status");
        assert!(page.contains("Being fixed"), "{page}");
        assert!(!page.contains("<soon>"), "escaped: {page}");

        // Enabling clears it.
        let on = admin(&dir, &["node", "enable", "toronto"]);
        assert_eq!(on.status.code(), Some(0), "{}", text(&on.stderr));
        wait_until("the note to go", 20, || {
            !running.get("/status").1.contains("back at 20:00")
        });
        let log = running.stop();
        assert!(
            !log.contains("uptime history"),
            "nothing went wrong with it: {log}"
        );

        // The history is in the database, so it survives a restart of the website.
        let again = server::Running::start(&[
            ("BC_DB", dir.join("control.db").display().to_string()),
            ("BC_NODES_DIR", dir.join("nodes").display().to_string()),
            ("BC_POLL_SECS", "2".to_string()),
        ]);
        wait_until("the uptime list again", 20, || {
            again
                .get("/status")
                .1
                .contains("<li><strong>Toronto</strong>: 100.0% over 1 day</li>")
        });
        again.stop();
    }

    #[test]
    fn a_busy_setting_that_cannot_be_read_does_not_stop_the_poller_and_the_page_uses_the_defaults()
    {
        let dir = dir("busybad");
        let node = fake_node();
        register(&dir, &node);
        let running = server::Running::start(&[
            ("BC_DB", dir.join("control.db").display().to_string()),
            ("BC_NODES_DIR", dir.join("nodes").display().to_string()),
            ("BC_POLL_SECS", "2".to_string()),
            ("BC_NODE_BUSY_LOAD", "banana".to_string()),
        ]);
        wait_until("/status to say Up", 20, || {
            running
                .get("/status")
                .1
                .contains("<span class=\"state up\">Up</span>")
        });
        let log = running.stop();
        assert!(
            log.contains("sign-in is off") && log.contains("BC_NODE_BUSY_LOAD"),
            "the reason is still logged: {log}"
        );
        assert!(log.contains("the node poller is on"), "{log}");
    }

    #[test]
    fn a_node_without_its_files_leaves_the_site_up_and_its_card_not_responding() {
        let dir = dir("nofiles");
        let added = admin(
            &dir,
            &[
                "node",
                "add",
                "toronto",
                "127.0.0.1:9",
                "Toronto",
                "Canada",
                "--protocol",
                "amneziawg",
            ],
        );
        assert_eq!(added.status.code(), Some(0));

        let running = server::Running::start(&[
            ("BC_DB", dir.join("control.db").display().to_string()),
            ("BC_NODES_DIR", dir.join("nodes").display().to_string()),
            ("BC_POLL_SECS", "2".to_string()),
        ]);
        wait_until("the card to say Down", 30, || {
            running
                .get("/")
                .1
                .contains("<span class=\"state down\">Down</span>")
        });
        let (_, page) = running.get("/status");
        assert!(
            page.contains("<span class=\"state down\">Down</span>"),
            "/status agrees: {page}"
        );
        let (status, _) = running.get("/healthz");
        let log = running.stop();

        assert_eq!(status, 200, "the site is up");
        assert!(log.contains("the secret file is missing"), "{log}");
    }

    #[test]
    fn without_a_database_the_poller_is_off_the_front_page_is_the_file_and_nothing_is_made() {
        let dir = dir("nodb");
        let db = dir.join("control.db");

        let running = server::Running::start(&[
            ("BC_DB", db.display().to_string()),
            ("BC_NODES_DIR", dir.join("nodes").display().to_string()),
        ]);
        let (status, front) = running.get("/");
        let log = running.stop();

        assert_eq!(status, 200);
        assert!(front.contains("Status unknown"), "the fixed cards");
        assert!(
            log.contains("the node poller is off") && log.contains("no database"),
            "{log}"
        );
        assert!(!db.exists());
    }

    #[test]
    fn a_poll_interval_outside_two_to_three_hundred_stops_the_server_and_names_the_setting() {
        for bad in ["1", "301", "abc", ""] {
            let out = Command::new(env!("CARGO_BIN_EXE_bf-control"))
                .env_clear()
                .env("BC_POLL_SECS", bad)
                .env("BC_LISTEN", "127.0.0.1:0")
                .output()
                .expect("the program starts");
            assert_eq!(out.status.code(), Some(1), "{bad:?}");
            assert!(
                text(&out.stderr).contains("BC_POLL_SECS"),
                "{bad:?}: {}",
                text(&out.stderr)
            );
        }
    }
}

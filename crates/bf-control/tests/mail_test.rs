//! Runs the real `bf-control mail-test` against a small fake Resend on this computer, to
//! prove the whole path: arguments, key file, request, answer, exit code, and that the
//! key never comes back out.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

const KEY: &str = "re_TESTKEY_abc123XYZ";

#[derive(Debug, Clone)]
struct Seen {
    request_line: String,
    headers: HashMap<String, String>,
    body: String,
}

struct Fake {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Fake {
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
    fn requests(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

/// A fake Resend that answers every request with `status` and `body`.
fn fake_resend(status: u16, body: &'static str) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut raw = Vec::new();
            let mut byte = [0u8; 1];
            // Read up to the blank line that ends the headers.
            while !raw.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                raw.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&raw).to_string();
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap_or("").to_string();
            let headers: HashMap<String, String> = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.trim().to_lowercase(), value.trim().to_string()))
                .collect();
            let length: usize = headers
                .get("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let mut request_body = vec![0u8; length];
            let _ = stream.read_exact(&mut request_body);
            log.lock().unwrap().push(Seen {
                request_line,
                headers,
                body: String::from_utf8_lossy(&request_body).to_string(),
            });
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    Fake { addr, seen }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bf-mail-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key_file(name: &str, mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_dir(name).join("resend.key");
    std::fs::write(&path, format!("{KEY}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn run(args: &[&str], url: &str, key_file: &PathBuf) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bf-control"))
        .args(args)
        .env("BC_RESEND_URL", url)
        .env("BC_RESEND_KEY_FILE", key_file)
        .env_remove("BC_DB")
        .output()
        .expect("the program starts")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn everything(out: &Output) -> String {
    format!("{}{}", text(&out.stdout), text(&out.stderr))
}

#[test]
fn it_sends_the_sign_in_email_to_the_address_and_reports_resends_id() {
    let fake = fake_resend(200, r#"{"id":"49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"}"#);
    let key = key_file("ok", 0o600);

    let out = run(&["mail-test", "lao@example.com"], &fake.url(), &key);

    assert_eq!(out.status.code(), Some(0), "{}", everything(&out));
    let said = text(&out.stdout);
    assert!(said.contains("lao@example.com"), "{said}");
    assert!(
        said.contains("49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"),
        "{said}"
    );
    assert!(!everything(&out).contains(KEY), "the key is never printed");

    let seen = fake.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].request_line, "POST /emails HTTP/1.1");
    assert_eq!(seen[0].headers["authorization"], format!("Bearer {KEY}"));
    assert!(seen[0].headers["idempotency-key"].starts_with("mail-test/"));
    let json: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(json["to"], serde_json::json!(["lao@example.com"]));
    assert_eq!(json["subject"], "Your Barely-free sign-in code");
    assert!(json["html"].as_str().unwrap().contains(">482917</td>"));
    assert!(!seen[0].body.contains(KEY));
}

#[test]
fn every_run_uses_a_new_idempotency_key_so_a_second_test_really_sends() {
    let fake = fake_resend(200, r#"{"id":"abc"}"#);
    let key = key_file("twice", 0o600);

    run(&["mail-test", "lao@example.com"], &fake.url(), &key);
    run(&["mail-test", "lao@example.com"], &fake.url(), &key);

    let seen = fake.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_ne!(
        seen[0].headers["idempotency-key"],
        seen[1].headers["idempotency-key"]
    );
}

#[test]
fn a_key_resend_rejects_exits_1_with_a_clear_message_and_no_key() {
    let fake = fake_resend(
        401,
        r#"{"statusCode":401,"name":"validation_error","message":"API key is invalid"}"#,
    );
    let key = key_file("rejected", 0o600);

    let out = run(&["mail-test", "lao@example.com"], &fake.url(), &key);

    assert_eq!(out.status.code(), Some(1));
    let said = text(&out.stderr);
    assert!(said.contains("does not accept the key"), "{said}");
    assert!(said.contains("API key is invalid"), "{said}");
    assert!(!everything(&out).contains(KEY));
    assert_eq!(fake.requests(), 1, "no retry for a bad key");
}

#[test]
fn a_bad_address_is_refused_before_anything_is_read_or_sent() {
    let fake = fake_resend(200, r#"{"id":"abc"}"#);
    let no_such_file = temp_dir("bad-address").join("missing.key");

    for bad in [
        "not-an-address",
        "Lao <lao@example.com>",
        "a@b.com, c@d.com",
    ] {
        let out = run(&["mail-test", bad], &fake.url(), &no_such_file);
        assert_eq!(out.status.code(), Some(1), "{bad}");
        assert!(text(&out.stderr).contains("not an email address"), "{bad}");
    }
    assert_eq!(fake.requests(), 0);
}

#[test]
fn a_missing_or_open_key_file_is_refused_before_any_request() {
    let fake = fake_resend(200, r#"{"id":"abc"}"#);

    let missing = temp_dir("missing").join("resend.key");
    let out = run(&["mail-test", "lao@example.com"], &fake.url(), &missing);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("key file"),
        "{}",
        text(&out.stderr)
    );

    let open = key_file("open", 0o644);
    let out = run(&["mail-test", "lao@example.com"], &fake.url(), &open);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("chmod 600"),
        "{}",
        text(&out.stderr)
    );
    assert!(!everything(&out).contains(KEY));

    assert_eq!(fake.requests(), 0);
}

#[test]
fn a_resend_address_that_is_not_https_and_not_this_computer_is_refused() {
    let key = key_file("http", 0o600);
    let out = run(
        &["mail-test", "lao@example.com"],
        "http://example.com",
        &key,
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("https"), "{}", text(&out.stderr));
}

#[test]
fn the_wrong_number_of_arguments_is_not_understood() {
    let fake = fake_resend(200, r#"{"id":"abc"}"#);
    let key = key_file("usage", 0o600);

    for args in [&["mail-test"][..], &["mail-test", "a@b.com", "c@d.com"]] {
        let out = run(args, &fake.url(), &key);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            text(&out.stderr).contains("mail-test <address>"),
            "{args:?}"
        );
    }
    assert_eq!(fake.requests(), 0);
}

#[test]
fn it_needs_no_database_and_touches_none() {
    let fake = fake_resend(200, r#"{"id":"abc"}"#);
    let key = key_file("nodb", 0o600);
    let db = temp_dir("nodb-db").join("control.db");

    let out = Command::new(env!("CARGO_BIN_EXE_bf-control"))
        .args(["mail-test", "lao@example.com"])
        .env("BC_RESEND_URL", fake.url())
        .env("BC_RESEND_KEY_FILE", &key)
        .env("BC_DB", &db)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "{}", everything(&out));
    assert!(!db.exists());
}

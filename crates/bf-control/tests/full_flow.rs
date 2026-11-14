//! The whole chain with the real program: the admin command gives an account a sign-in
//! address, the real server starts from its settings, a code is asked for (the real Resend
//! client talks to a fake Resend on this computer), the code is typed, and the account
//! page opens. Then the same server is stopped and the log is read for anything that
//! should never be in it.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};

const RESEND_KEY: &str = "re_SECRETKEY_full_flow_1234";
const ADDRESS: &str = "lao@example.com";

/// A fake Resend that accepts every email and remembers the request bodies.
fn fake_resend() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let log = bodies.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut raw = Vec::new();
            let mut byte = [0u8; 1];
            while !raw.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                raw.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&raw).to_lowercase();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; length];
            let _ = stream.read_exact(&mut body);
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&body).to_string());
            let answer = r#"{"id":"full-flow-1"}"#;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                answer.len()
            );
        }
    });
    (port, bodies)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server {
    child: Child,
}

impl Server {
    fn stop(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut log = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            let _ = stderr.read_to_string(&mut log);
        }
        log
    }
}

#[tokio::test]
async fn the_admin_command_the_real_server_and_the_real_mail_client_make_a_working_sign_in() {
    let dir = std::env::temp_dir().join(format!("bf-full-flow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (db, key, resend_key) = (
        dir.join("control.db"),
        dir.join("control.key"),
        dir.join("resend.key"),
    );
    std::fs::write(&resend_key, format!("{RESEND_KEY}\n")).unwrap();
    std::fs::set_permissions(&resend_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let program = env!("CARGO_BIN_EXE_bf-control");

    // 1. The admin makes an account that can sign in.
    let made = Command::new(program)
        .args(["account", "add", "lao", "--email", ADDRESS])
        .env_clear()
        .env("BC_DB", &db)
        .env("BC_KEY_FILE", &key)
        .output()
        .unwrap();
    assert_eq!(
        made.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    assert!(key.exists());

    // 2. The server starts from its settings.
    let (resend_port, bodies) = fake_resend();
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let child = Command::new(program)
        .env_clear()
        .env("BC_LISTEN", format!("127.0.0.1:{port}"))
        .env("BC_DB", &db)
        .env("BC_KEY_FILE", &key)
        .env("BC_RESEND_KEY_FILE", &resend_key)
        .env("BC_RESEND_URL", format!("http://127.0.0.1:{resend_port}"))
        .env("BC_ORIGINS", &origin)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let server = Server { child };
    let started = Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the server did not start"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let c = Client::builder().redirect(Policy::none()).build().unwrap();
    let form = "application/x-www-form-urlencoded";

    // 3. Ask for a code.
    let asked = c
        .post(format!("{origin}/signin"))
        .header("origin", &origin)
        .header("content-type", form)
        .body("email=lao%40example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(asked.status(), StatusCode::SEE_OTHER);
    assert_eq!(asked.headers()["location"], "/verify");
    let pending = asked.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(pending.starts_with("__Host-bf_pending="), "{pending}");
    let verify_page = c
        .get(format!("{origin}/verify"))
        .header("cookie", &pending)
        .send()
        .await
        .unwrap();
    assert_eq!(verify_page.status(), StatusCode::OK);
    assert!(verify_page.text().await.unwrap().contains(ADDRESS));

    // 4. The email goes out through the real client to the fake Resend.
    let body = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(body) = bodies.lock().unwrap().first() {
                break body.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("an email reached the fake Resend");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["to"], serde_json::json!([ADDRESS]));
    assert_eq!(json["subject"], "Your Barely-free sign-in code");
    let text = json["text"].as_str().unwrap();
    let code = text
        .lines()
        .map(str::trim)
        .find(|line| line.len() == 6 && line.bytes().all(|b| b.is_ascii_digit()))
        .expect("the code is on a line of its own")
        .to_string();

    // 5. Type the code, and the account page opens.
    let signed_in = c
        .post(format!("{origin}/verify"))
        .header("origin", &origin)
        .header("cookie", &pending)
        .header("content-type", form)
        .body(format!("code={code}"))
        .send()
        .await
        .unwrap();
    assert_eq!(signed_in.status(), StatusCode::SEE_OTHER);
    let cookie = signed_in.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let account = c
        .get(format!("{origin}/account"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(account.status(), StatusCode::OK);
    assert!(account.text().await.unwrap().contains("lao"));

    // 6. Nothing that should stay secret is in the log, and the database has no address.
    let log = server.stop();
    assert!(log.contains("sign-in pages are on"), "{log}");
    let pending_value = pending.split('=').nth(1).unwrap().to_string();
    for secret in [
        RESEND_KEY,
        ADDRESS,
        code.as_str(),
        cookie.as_str(),
        pending_value.as_str(),
    ] {
        assert!(!log.contains(secret), "{secret} is in the log: {log}");
    }
    let stored = std::fs::read(&db).unwrap();
    assert!(
        !stored
            .windows(ADDRESS.len())
            .any(|w| w == ADDRESS.as_bytes()),
        "the address is in the database file"
    );
}

#[tokio::test]
async fn open_sign_up_with_the_real_server_and_mail_client_makes_an_account_from_nothing() {
    const NEW_ADDRESS: &str = "new.person@example.com";
    let dir = std::env::temp_dir().join(format!("bf-full-flow-open-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (db, key, resend_key) = (
        dir.join("control.db"),
        dir.join("control.key"),
        dir.join("resend.key"),
    );
    bf_control::secrets::ControlKeys::load_or_create(&key).unwrap();
    std::fs::write(&resend_key, format!("{RESEND_KEY}\n")).unwrap();
    std::fs::set_permissions(&resend_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let program = env!("CARGO_BIN_EXE_bf-control");

    // No account is made by hand: the database does not even exist yet.
    let (resend_port, bodies) = fake_resend();
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let child = Command::new(program)
        .env_clear()
        .env("BC_LISTEN", format!("127.0.0.1:{port}"))
        .env("BC_DB", &db)
        .env("BC_KEY_FILE", &key)
        .env("BC_RESEND_KEY_FILE", &resend_key)
        .env("BC_RESEND_URL", format!("http://127.0.0.1:{resend_port}"))
        .env("BC_ORIGINS", &origin)
        .env("BC_OPEN_SIGNUP", "1")
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let server = Server { child };
    let started = Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the server did not start"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let c = Client::builder().redirect(Policy::none()).build().unwrap();
    let form = "application/x-www-form-urlencoded";

    let asked = c
        .post(format!("{origin}/signin"))
        .header("origin", &origin)
        .header("content-type", form)
        .body("email=new.person%40example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(asked.status(), StatusCode::SEE_OTHER);
    let pending = asked.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let body = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(body) = bodies.lock().unwrap().first() {
                break body.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("an email reached the fake Resend");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["to"], serde_json::json!([NEW_ADDRESS]));
    let code = json["text"]
        .as_str()
        .unwrap()
        .lines()
        .map(str::trim)
        .find(|line| line.len() == 6 && line.bytes().all(|b| b.is_ascii_digit()))
        .expect("the code is on a line of its own")
        .to_string();

    let signed_in = c
        .post(format!("{origin}/verify"))
        .header("origin", &origin)
        .header("cookie", &pending)
        .header("content-type", form)
        .body(format!("code={code}"))
        .send()
        .await
        .unwrap();
    assert_eq!(signed_in.status(), StatusCode::SEE_OTHER);
    assert_eq!(signed_in.headers()["location"], "/account");
    let cookie = signed_in.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let account = c
        .get(format!("{origin}/account"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(account.status(), StatusCode::OK);
    assert!(account.text().await.unwrap().contains("member-1"));

    let log = server.stop();
    assert!(log.contains("sign-up is open"), "{log}");
    assert!(log.contains("a new account was made"), "{log}");
    let pending_value = pending.split('=').nth(1).unwrap().to_string();
    for secret in [
        RESEND_KEY,
        NEW_ADDRESS,
        code.as_str(),
        cookie.as_str(),
        pending_value.as_str(),
    ] {
        assert!(!log.contains(secret), "{secret} is in the log: {log}");
    }
    let stored = std::fs::read(&db).unwrap();
    assert!(
        !stored
            .windows(NEW_ADDRESS.len())
            .any(|w| w == NEW_ADDRESS.as_bytes()),
        "the address is in the database file"
    );
}

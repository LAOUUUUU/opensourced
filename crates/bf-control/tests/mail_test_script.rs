//! Runs the real `deploy/mail-test.sh` with a stand-in for `bf-control`, to prove it
//! hands the key over in a private temporary file, never on a command line or screen,
//! and removes the file whatever happens.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const KEY: &str = "re_SCRIPTKEY_987zyx";

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/mail-test.sh")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bf-script-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A stand-in `bf-control` that records what it was given and exits with `$STUB_EXIT`.
fn stub(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("stub");
    std::fs::write(
        &path,
        "#!/bin/sh\n\
         {\n\
           echo \"args: $*\"\n\
           echo \"keyfile: $BC_RESEND_KEY_FILE\"\n\
           echo \"mode: $(ls -l \"$BC_RESEND_KEY_FILE\" | cut -c1-10)\"\n\
           echo \"content: $(cat \"$BC_RESEND_KEY_FILE\")\"\n\
         } > \"$RECORD\"\n\
         [ -n \"$STUB_SLEEP\" ] && sleep \"$STUB_SLEEP\"\n\
         exit ${STUB_EXIT:-0}\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Runs the script with `typed` on its standard input, the way a person types the key.
fn run(dir: &Path, args: &[&str], typed: &str, exit: &str) -> Output {
    let mut child = Command::new("bash")
        .arg(script())
        .args(args)
        .env("BF_BIN", stub(dir))
        .env("RECORD", dir.join("record"))
        .env("STUB_EXIT", exit)
        .env("TMPDIR", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("bash starts");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(typed.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn record(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("record")).unwrap_or_default()
}

fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.starts_with("bf-resend-key"))
        .collect()
}

#[test]
fn the_script_hands_the_key_over_in_a_private_file_and_removes_it() {
    let dir = temp_dir("ok");

    let out = run(&dir, &["lao@example.com"], &format!("{KEY}\n"), "0");

    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seen = record(&dir);
    assert!(seen.contains("args: mail-test lao@example.com"), "{seen}");
    assert!(seen.contains(&format!("content: {KEY}")), "{seen}");
    assert!(
        seen.contains("mode: -rw-------"),
        "private to its owner: {seen}"
    );
    assert!(
        !seen.contains(&format!("args: {KEY}")),
        "never on a command line"
    );
    assert!(
        leftovers(&dir).is_empty(),
        "the temporary file is gone: {:?}",
        leftovers(&dir)
    );
    for stream in [&out.stdout, &out.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(KEY),
            "the key is not echoed"
        );
    }
}

#[test]
fn the_file_is_removed_when_the_send_fails_too() {
    let dir = temp_dir("fail");

    let out = run(&dir, &["lao@example.com"], &format!("{KEY}\n"), "1");

    assert_eq!(out.status.code(), Some(1));
    assert!(record(&dir).contains(&format!("content: {KEY}")));
    assert!(leftovers(&dir).is_empty(), "{:?}", leftovers(&dir));
}

#[test]
fn no_key_or_no_address_means_nothing_is_run() {
    let dir = temp_dir("empty");
    let out = run(&dir, &["lao@example.com"], "\n", "0");
    assert_eq!(out.status.code(), Some(1));
    assert!(record(&dir).is_empty(), "the program was not started");
    assert!(leftovers(&dir).is_empty());

    let dir = temp_dir("noaddr");
    let out = run(&dir, &[], &format!("{KEY}\n"), "0");
    assert_ne!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
    assert!(record(&dir).is_empty());
}

#[test]
fn the_script_is_valid_bash_and_never_puts_the_key_in_a_command() {
    let status = Command::new("bash")
        .arg("-n")
        .arg(script())
        .status()
        .unwrap();
    assert!(status.success());

    let text = std::fs::read_to_string(script()).unwrap();
    assert!(text.contains("read -rs"), "hidden prompt");
    assert!(!text.contains("echo \"$key\""), "never echoes the key");
    assert!(!text.contains("--key"), "no key on a command line");
    assert!(text.contains("trap"), "cleans up on exit");
}

#[test]
fn the_file_is_removed_when_the_script_is_stopped_while_it_runs() {
    let dir = temp_dir("stopped");
    let mut child = Command::new("bash")
        .arg(script())
        .arg("lao@example.com")
        .env("BF_BIN", stub(&dir))
        .env("RECORD", dir.join("record"))
        .env("STUB_SLEEP", "2")
        .env("TMPDIR", &dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{KEY}\n").as_bytes())
        .unwrap();
    // Wait until the program has started, so the key file exists.
    for _ in 0..100 {
        if dir.join("record").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(dir.join("record").exists(), "the program started");

    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    let status = child.wait().unwrap();

    assert_ne!(status.code(), Some(0));
    assert!(leftovers(&dir).is_empty(), "{:?}", leftovers(&dir));
}

//! Runs the real `deploy/bf-backup-receive`, the forced command of the VM's backup key on a
//! node, against a folder of its own. It may only add one well-named file of a sane size,
//! never write over one, and keeps the newest few. Spec: `specs/backup.md`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const NAME: &str = "control-20261112T031500Z.tar.age";

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/bf-backup-receive")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bf-receive-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs the receiver as sshd would: the client's request in `SSH_ORIGINAL_COMMAND`, the
/// file on standard input.
fn receive(dir: &Path, request: &str, body: &[u8], keep: u32, max: u64) -> Output {
    let mut child = Command::new("/bin/sh")
        .arg(script())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("SSH_ORIGINAL_COMMAND", request)
        .env("BF_BACKUP_DIR", dir)
        .env("BF_BACKUP_KEEP", keep.to_string())
        .env("BF_BACKUP_MAX", max.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A refusal may close standard input early; that is not the test's failure.
    let _ = child.stdin.take().unwrap().write_all(body);
    child.wait_with_output().unwrap()
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn said(output: &Output) -> String {
    format!(
        "status {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_good_upload_is_kept_byte_for_byte_and_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("good");
    let body: Vec<u8> = (0..5000u32).map(|n| (n % 251) as u8).collect();
    let output = receive(&dir, &format!("put {NAME}"), &body, 30, 1 << 20);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    assert_eq!(names(&dir), [NAME]);
    assert_eq!(std::fs::read(dir.join(NAME)).unwrap(), body);
    let mode = std::fs::metadata(dir.join(NAME))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn anything_but_one_well_named_put_is_refused_and_leaves_nothing() {
    let dir = temp_dir("names");
    for request in [
        "",
        "put",
        "get control-20261112T031500Z.tar.age",
        "put control-20261112T031500Z.tar.age extra",
        "put control-20261112T031500Z.tar.age;rm -rf /",
        "put ../control-20261112T031500Z.tar.age",
        "put a/control-20261112T031500Z.tar.age",
        "put control-2026111T031500Z.tar.age",
        "put control-20261112T031500.tar.age",
        "put control-20261112T031500Z.tar",
        "put Control-20261112T031500Z.tar.age",
        "put control-2026111xT031500Z.tar.age",
        " put control-20261112T031500Z.tar.age",
        "scp -t /var/lib/bf-backup",
    ] {
        let output = receive(&dir, request, b"data", 30, 1 << 20);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{request:?}: {}",
            said(&output)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("only"),
            "{request:?}: {}",
            said(&output)
        );
        assert!(names(&dir).is_empty(), "{request:?} left {:?}", names(&dir));
    }
}

#[test]
fn an_existing_name_is_refused_and_left_alone() {
    let dir = temp_dir("existing");
    std::fs::write(dir.join(NAME), "first").unwrap();
    let output = receive(&dir, &format!("put {NAME}"), b"second", 30, 1 << 20);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("already there"));
    assert_eq!(std::fs::read_to_string(dir.join(NAME)).unwrap(), "first");
    assert_eq!(names(&dir), [NAME]);
}

#[test]
fn an_upload_over_the_cap_is_refused_and_leaves_nothing() {
    let dir = temp_dir("cap");
    let output = receive(&dir, &format!("put {NAME}"), &[7u8; 1001], 30, 1000);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("over 1000 bytes"));
    assert!(names(&dir).is_empty(), "{:?}", names(&dir));

    let output = receive(&dir, &format!("put {NAME}"), &[7u8; 1000], 30, 1000);
    assert_eq!(
        output.status.code(),
        Some(0),
        "exactly the cap is fine: {}",
        said(&output)
    );
    assert_eq!(names(&dir), [NAME]);
}

#[test]
fn an_empty_upload_is_refused() {
    let dir = temp_dir("empty");
    let output = receive(&dir, &format!("put {NAME}"), b"", 30, 1000);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(names(&dir).is_empty(), "{:?}", names(&dir));
}

#[test]
fn only_the_newest_are_kept_and_other_files_are_not_touched() {
    let dir = temp_dir("keep");
    for day in 1..=4 {
        std::fs::write(
            dir.join(format!("control-2026110{day}T031500Z.tar.age")),
            "old",
        )
        .unwrap();
    }
    std::fs::write(dir.join("notes.txt"), "mine").unwrap();
    let output = receive(&dir, &format!("put {NAME}"), b"new", 3, 1000);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    assert_eq!(
        names(&dir),
        [
            "control-20261103T031500Z.tar.age",
            "control-20261104T031500Z.tar.age",
            NAME,
            "notes.txt",
        ]
    );
}

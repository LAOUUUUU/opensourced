//! Runs the real `bf-agent trackers build` on temporary files: the daily list update on a
//! node calls exactly this (`specs/trackers.md`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_bf-agent");

struct Dir(PathBuf);

impl Dir {
    fn new(label: &str) -> Dir {
        let dir =
            std::env::temp_dir().join(format!("bf-agent-trackers-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An EasyPrivacy-like list of `n` domain rules, plus lines that must be skipped.
fn list_of(n: usize) -> String {
    let mut text = String::from("[Adblock Plus 2.0]\n! Title: EasyPrivacy\n");
    for i in 0..n {
        text.push_str(&format!("||t{i}.example^\n"));
    }
    text.push_str("||skip.example^$third-party\nexample.com##.pixel\n");
    text
}

fn build(dir: &Dir, list: &Path, allow: &Path, zone: &Path) -> Output {
    Command::new(BIN)
        .args(["trackers", "build"])
        .arg(list)
        .arg(allow)
        .arg(zone)
        .current_dir(&dir.0)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn it_writes_the_zone_and_says_how_many_names_it_holds_now_and_before() {
    let dir = Dir::new("writes");
    std::fs::write(dir.file("list.txt"), list_of(1_200)).unwrap();
    std::fs::write(dir.file("allow.txt"), "# allowed\nt0.example\n").unwrap();

    let out = build(
        &dir,
        &dir.file("list.txt"),
        &dir.file("allow.txt"),
        &dir.file("trackers.rpz"),
    );

    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "trackers: 1199 names (was 0)\n");
    let zone = std::fs::read_to_string(dir.file("trackers.rpz")).unwrap();
    let expected: Vec<String> =
        bf_common::trackers::names(&list_of(1_200), "# allowed\nt0.example\n");
    assert_eq!(zone, bf_common::trackers::zone(&expected));
    assert!(!zone.contains("t0.example CNAME"));
    assert!(!zone.contains("skip.example"));
    assert!(!dir.file("trackers.rpz.tmp").exists());
}

#[test]
fn a_list_that_breaks_the_floor_is_refused_and_the_zone_in_force_is_kept() {
    let dir = Dir::new("floor");
    let in_force: Vec<String> = (0..3_000).map(|i| format!("old{i}.example")).collect();
    let zone_text = bf_common::trackers::zone(&in_force);
    std::fs::write(dir.file("trackers.rpz"), &zone_text).unwrap();
    std::fs::write(dir.file("list.txt"), list_of(1_200)).unwrap();
    std::fs::write(dir.file("allow.txt"), "").unwrap();

    let out = build(
        &dir,
        &dir.file("list.txt"),
        &dir.file("allow.txt"),
        &dir.file("trackers.rpz"),
    );

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stdout), "");
    assert!(
        text(&out.stderr).contains(
            "refused, the zone in force is kept: 1200 names, under half of the 3000 in force"
        ),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(dir.file("trackers.rpz")).unwrap(),
        zone_text
    );
}

#[test]
fn a_missing_input_writes_nothing_and_fails_and_wrong_words_are_a_usage_error() {
    let dir = Dir::new("missing");
    std::fs::write(dir.file("list.txt"), list_of(1_200)).unwrap();
    for (list, allow) in [("list.txt", "no-allow.txt"), ("no-list.txt", "list.txt")] {
        let out = build(
            &dir,
            &dir.file(list),
            &dir.file(allow),
            &dir.file("trackers.rpz"),
        );
        assert_eq!(out.status.code(), Some(1), "{list} {allow}");
        assert!(
            text(&out.stderr).contains("cannot read the"),
            "{}",
            text(&out.stderr)
        );
        assert!(!dir.file("trackers.rpz").exists());
    }
    for args in [
        vec!["trackers"],
        vec!["trackers", "build"],
        vec!["trackers", "build", "a", "b"],
        vec!["trackers", "build", "a", "b", "c", "d"],
        vec!["trackers", "make", "a", "b", "c"],
    ] {
        let out = Command::new(BIN).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(text(&out.stderr).contains("usage:"), "{args:?}");
    }
}

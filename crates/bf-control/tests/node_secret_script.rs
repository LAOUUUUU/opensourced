//! Runs the real `deploy/set-node-secret.sh` with a stand-in `ssh`, to prove the secret
//! travels from the node to the VM unchanged through a pipe and nowhere else: not on a
//! command line, not on screen. The stand-in also runs the VM-side commands against a
//! folder of their own, so what the VM would install (and refuse) is checked for real.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SECRET: &str = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0";

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/set-node-secret.sh")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bf-nodesecret-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A world to run the script in: `bin` has stand-ins for `ssh` and the commands a VM has
/// that this Mac may not; `vm` is the VM's `/etc`; the node's secret file is `node_secret`.
struct World {
    dir: PathBuf,
}

fn world(name: &str, node_secret: &str) -> World {
    let dir = temp_dir(name);
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::create_dir_all(dir.join("vm")).unwrap();
    std::fs::write(dir.join("node_secret"), node_secret).unwrap();

    // `ssh`: the first word that mentions "node.example" or "vm.example" says which end.
    executable(
        &dir.join("bin/ssh"),
        r#"#!/bin/bash
all="$*"
last="${!#}"
echo "ssh $all" >> "$RECORD/ssh_calls"
case "$all" in
  *node.example*)
    case "$last" in
      "cat /etc/barely-free/agent"*".secret") [ -z "$NODE_FAILS" ] || exit 1; cat "$NODE_SECRET"; [ -z "$NODE_DIES_AFTER" ] || exit 1 ;;
      "sha256sum /etc/barely-free/agent"*".secret") printf '%s  agent.secret\n' "$(h "$NODE_SECRET")" ;;
      "test -e /etc/barely-free/agent-"*".secret")
        [ -z "$NODE_TEST_FAILS" ] || exit 255
        f=${last#test -e /etc/barely-free/}
        case " $NODE_SECOND_SECRETS " in *" $f "*) exit 0 ;; *) exit 1 ;; esac ;;
      *) echo "unexpected node command: $last" >&2; exit 9 ;;
    esac ;;
  *vm.example*)
    case "$last" in
      sha256sum*) if [ -n "$VM_HASH_FAKE" ]; then printf '%s  file\n' "$VM_HASH_FAKE"; else printf '%s  file\n' "$(h "$VM_ROOT/etc/barely-free/nodes/$(basename "${last#sha256sum }")" 2>/dev/null || echo 00000000)"; fi ;;
      *) command=${last//\/etc\/barely-free/$VM_ROOT/etc/barely-free}
         tee "$RECORD/vm_stdin" | sh -c "$command" ;;
    esac ;;
  *) echo "unexpected host: $all" >&2; exit 9 ;;
esac
"#,
    );
    // `h FILE`: the SHA-256 of a file, whichever tool this machine has.
    executable(
        &dir.join("bin/h"),
        "#!/bin/sh\nif command -v sha256sum >/dev/null 2>&1; then sha256sum \"$1\" | cut -d' ' -f1; else shasum -a 256 \"$1\" | cut -d' ' -f1; fi\n",
    );
    // What the VM has and a Mac may not.
    executable(&dir.join("bin/getent"), "#!/bin/sh\nexit 0\n");
    executable(
        &dir.join("bin/chown"),
        "#!/bin/sh\necho \"chown $*\" >> \"$RECORD/chown\"\n",
    );
    executable(
        &dir.join("bin/install"),
        "#!/bin/sh\nfor last; do :; done\nwhile [ $# -gt 0 ]; do case \"$1\" in -d|-o|-g|-m) [ \"$1\" = -d ] || shift ;; *) mkdir -p \"$1\" ;; esac; shift; done\n",
    );
    // `sha256sum` on the VM side of the stand-in: the script calls it through ssh, which the
    // stand-in answers itself, so nothing else is needed here.
    World { dir }
}

impl World {
    fn run(&self, args: &[&str], extra: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        let mut command = Command::new("bash");
        command
            .arg(script())
            .args(args)
            .env("PATH", path)
            .env("RECORD", &self.dir)
            .env("NODE_SECRET", self.dir.join("node_secret"))
            .env("VM_ROOT", self.dir.join("vm"))
            .env("TMPDIR", &self.dir)
            .stdin(std::process::Stdio::null());
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().expect("bash starts")
    }

    fn installed(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(
            self.dir
                .join(format!("vm/etc/barely-free/nodes/{name}.secret")),
        )
        .ok()
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(self.dir.join("ssh_calls")).unwrap_or_default()
    }

    fn leftovers(&self) -> Vec<String> {
        std::fs::read_dir(self.dir.join("vm/etc/barely-free/nodes"))
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n.starts_with('.'))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

const GOOD: [&str; 3] = [
    "toronto",
    "root@node.example -i ~/.ssh/key -o IdentitiesOnly=yes",
    "root@vm.example -o Port=2222",
];

#[test]
fn the_secret_goes_node_to_vm_unchanged_in_mode_0400_and_is_never_shown() {
    let world = world("good", &format!("{SECRET}\n"));

    let out = world.run(&GOOD, &[]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        world.installed("toronto").as_deref(),
        Some(format!("{SECRET}\n").as_str())
    );
    let mode = std::fs::metadata(world.dir.join("vm/etc/barely-free/nodes/toronto.secret"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o400);
    assert!(world.leftovers().is_empty(), "{:?}", world.leftovers());
    let chowns = std::fs::read_to_string(world.dir.join("chown")).unwrap();
    assert!(chowns.contains("barely-free:barely-free"), "{chowns}");

    let shown = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(!shown.contains(SECRET), "never on screen: {shown}");
    assert!(
        world.calls().matches(SECRET).count() == 0,
        "never on a command line"
    );
    assert!(shown.contains("they match"), "{shown}");
    let first8 = &std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("h {} ", world.dir.join("node_secret").display()))
        .env(
            "PATH",
            format!(
                "{}:{}",
                world.dir.join("bin").display(),
                std::env::var("PATH").unwrap()
            ),
        )
        .output()
        .unwrap()
        .stdout;
    assert!(
        shown.contains(&text(first8)[..8]),
        "the fingerprint is printed: {shown}"
    );
    assert!(
        !shown.contains(&text(first8)[..9]),
        "and only 8 characters of it"
    );
    assert_eq!(
        std::fs::read_to_string(world.dir.join("vm_stdin")).unwrap(),
        format!("{SECRET}\n"),
        "what the second ssh was given is exactly what the first one read"
    );
}

#[test]
fn the_script_keeps_the_secret_off_the_mac_entirely() {
    let source = std::fs::read_to_string(script()).unwrap();

    assert!(
        source.contains("| ssh \"${vm[@]}\""),
        "one ssh piped into the other"
    );
    for forbidden in [
        "> /tmp",
        "> \"$TMPDIR",
        "mktemp /tmp",
        "echo \"$secret",
        "secret=$(",
        "read -rs",
    ] {
        assert!(!source.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn something_that_is_not_a_hex_secret_is_refused_by_the_vm_and_nothing_is_installed() {
    for (what, content) in [
        ("short", "abcd\n"),
        (
            "63 characters is one short",
            &format!("{}\n", "a".repeat(63)),
        ),
        (
            "an odd number of characters",
            &format!("{}\n", "a".repeat(65)),
        ),
        (
            "two lines",
            &format!("{}\n{}\n", "a".repeat(64), "b".repeat(64)),
        ),
        (
            "a space inside",
            &format!("{} {}\n", "a".repeat(40), "b".repeat(40)),
        ),
        ("not hex", &format!("{}zz\n", "ab".repeat(33))),
        ("empty", ""),
        (
            "a sentence",
            "this is not a secret at all, just words, quite a lot of words really\n",
        ),
    ] {
        let world = world("refused", content);

        let out = world.run(&GOOD, &[]);

        assert_ne!(out.status.code(), Some(0), "{what}");
        assert!(
            text(&out.stderr).contains("nothing was installed"),
            "{what}: {}",
            text(&out.stderr)
        );
        assert_eq!(world.installed("toronto"), None, "{what}");
        assert!(
            world.leftovers().is_empty(),
            "{what}: the half-written file is removed"
        );
        assert!(!text(&out.stdout).contains("they match"), "{what}");
    }
}

#[test]
fn a_node_that_cannot_be_read_stops_the_script_and_installs_nothing() {
    let world = world("nodefails", &format!("{SECRET}\n"));

    let out = world.run(&GOOD, &[("NODE_FAILS", "1")]);

    assert_ne!(out.status.code(), Some(0));
    assert_eq!(world.installed("toronto"), None);
}

#[test]
fn a_node_that_dies_after_sending_the_secret_makes_the_script_fail() {
    let world = world("dies", &format!("{SECRET}\n"));

    let out = world.run(&GOOD, &[("NODE_DIES_AFTER", "1")]);

    assert_ne!(
        out.status.code(),
        Some(0),
        "a pipeline whose first end failed is not a success: {}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
}

#[test]
fn copies_that_differ_are_reported_and_fail() {
    let world = world("differ", &format!("{SECRET}\n"));

    let out = world.run(&GOOD, &[("VM_HASH_FAKE", "deadbeefdeadbeef")]);

    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("DO NOT MATCH"),
        "{}",
        text(&out.stderr)
    );
    assert!(!text(&out.stdout).contains("they match"));
}

#[test]
fn a_second_run_replaces_the_first_copy() {
    let world = world("again", &format!("{SECRET}\n"));
    assert_eq!(world.run(&GOOD, &[]).status.code(), Some(0));
    std::fs::write(
        world.dir.join("node_secret"),
        format!("{}\n", "ab".repeat(32)),
    )
    .unwrap();

    let out = world.run(&GOOD, &[]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        world.installed("toronto").as_deref(),
        Some(format!("{}\n", "ab".repeat(32)).as_str())
    );
}

#[test]
fn a_bad_name_or_missing_arguments_stop_it_before_any_ssh() {
    let world = world("badargs", &format!("{SECRET}\n"));
    for name in [
        "Toronto",
        "../etc",
        "a b",
        "-x",
        "",
        "toronto-",
        "1node",
        &"a".repeat(33),
    ] {
        let out = world.run(&[name, GOOD[1], GOOD[2]], &[]);
        assert_ne!(out.status.code(), Some(0), "{name:?}");
    }
    for args in [&[][..], &["toronto"], &["toronto", GOOD[1]]] {
        let out = world.run(args, &[]);
        assert_ne!(out.status.code(), Some(0), "{args:?}");
        assert!(
            text(&out.stderr).contains("usage:"),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
    assert_eq!(world.calls(), "", "no ssh was started");
}

#[test]
fn a_second_agents_secret_is_read_from_the_file_named_and_the_first_agents_by_default() {
    let world = world("second", &format!("{SECRET}\n"));

    let out = world.run(&GOOD, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        world.calls().contains("cat /etc/barely-free/agent.secret"),
        "{}",
        world.calls()
    );

    let out = world.run(
        &[
            "toronto-wg",
            GOOD[1],
            GOOD[2],
            "/etc/barely-free/agent-toronto-wg.secret",
        ],
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let calls = world.calls();
    assert!(
        calls.contains("cat /etc/barely-free/agent-toronto-wg.secret"),
        "{calls}"
    );
    assert!(
        calls.contains("sha256sum /etc/barely-free/agent-toronto-wg.secret"),
        "{calls}"
    );
    assert_eq!(
        world.installed("toronto-wg").as_deref(),
        Some(format!("{SECRET}\n").as_str())
    );
}

#[test]
fn a_second_agents_name_without_its_file_is_refused_before_the_first_agents_secret_is_read() {
    // Without the fourth argument the script reads agent.secret: the first agent's. For a
    // name that has its own agent-<name>.secret on the server, that would put the wrong
    // secret on the VM under the second agent's name.
    let world = world("noflag", &format!("{SECRET}\n"));

    let out = world.run(
        &["toronto-wg", GOOD[1], GOOD[2]],
        &[(
            "NODE_SECOND_SECRETS",
            "agent-toronto-wg.secret agent-x.secret",
        )],
    );

    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("/etc/barely-free/agent-toronto-wg.secret"),
        "it says which file to give: {}",
        text(&out.stderr)
    );
    let calls = world.calls();
    assert!(
        calls.contains("test -e /etc/barely-free/agent-toronto-wg.secret"),
        "{calls}"
    );
    assert!(!calls.contains("cat "), "nothing was read: {calls}");
    assert!(
        !calls.contains("vm.example"),
        "the VM was not touched: {calls}"
    );
    assert_eq!(world.installed("toronto-wg"), None);

    // A name with no file of its own is a first agent: agent.secret, as before.
    let out = world.run(&GOOD, &[("NODE_SECOND_SECRETS", "agent-toronto-wg.secret")]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(world.calls().contains("cat /etc/barely-free/agent.secret"));
}

#[test]
fn a_node_that_cannot_be_asked_about_a_second_agent_stops_the_script() {
    let world = world("testfails", &format!("{SECRET}\n"));

    let out = world.run(&GOOD, &[("NODE_TEST_FAILS", "1")]);

    assert_ne!(out.status.code(), Some(0));
    assert!(!world.calls().contains("cat "), "{}", world.calls());
    assert_eq!(world.installed("toronto"), None);
}

#[test]
fn a_secret_file_that_is_not_an_agents_is_refused_before_any_ssh() {
    let world = world("badfile", &format!("{SECRET}\n"));
    for file in [
        "/etc/shadow",
        "/etc/barely-free/agent.secret.bak",
        "/etc/barely-free/agent-../x.secret",
        "/etc/barely-free/agent-.secret",
        "/etc/barely-free/agent-a b.secret",
        "etc/barely-free/agent-x.secret",
        "/etc/barely-free/nodes/x.secret",
    ] {
        let out = world.run(&["toronto-wg", GOOD[1], GOOD[2], file], &[]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{file:?}: {}",
            text(&out.stderr)
        );
    }
    let out = world.run(
        &[
            "toronto-wg",
            GOOD[1],
            GOOD[2],
            "/etc/barely-free/agent-x.secret",
            "extra",
        ],
        &[],
    );
    assert_eq!(out.status.code(), Some(2), "too many arguments");
    assert_eq!(world.calls(), "", "no ssh was started");
}

#[test]
fn the_script_is_valid_shell() {
    let status = Command::new("bash")
        .arg("-n")
        .arg(script())
        .status()
        .unwrap();
    assert!(status.success());
}

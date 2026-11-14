//! Runs the real `deploy/set-admin-password.sh` with a stand-in `ssh` that hands what it is
//! given to the real `bf-control` program on a database of its own. That proves the password
//! travels from the hidden prompt to `admin set-password` through one pipe and nowhere else:
//! not on a command line, not on screen, not in a file. It also proves what the program does
//! with it: only an Argon2id hash is kept, and it checks out against exactly what was typed.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use bf_control::adminauth::verify_password;

/// A test value, not a real password.
const PASSWORD: &str = "correct horse battery staple";

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/set-admin-password.sh")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bf-adminpw-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

/// A world to run the script in: a `bin` with stand-ins for `ssh` and `runuser`, and a
/// database that the real program (standing in for the one on the VM) works on.
struct World {
    dir: PathBuf,
    db: PathBuf,
}

fn world(name: &str) -> World {
    let dir = temp_dir(name);
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    let db = dir.join("control.db");

    // `ssh`: records what it was asked, runs the remote command here with the real program
    // in place of the installed one, and passes standard input through.
    executable(
        &dir.join("bin/ssh"),
        r#"#!/bin/bash
all="$*"
last="${!#}"
echo "ssh $all" >> "$RECORD/ssh_calls"
[ -z "$SSH_FAILS" ] || { echo "ssh: connect to host failed" >&2; exit 255; }
command=${last//\/usr\/local\/bin\/bf-control/$BF_CONTROL}
tee "$RECORD/vm_stdin" | sh -c "$command"
"#,
    );
    // `runuser -u barely-free -- command...`: runs the command, and says who it was for.
    executable(
        &dir.join("bin/runuser"),
        "#!/bin/sh\necho \"runuser $*\" >> \"$RECORD/runuser_calls\"\nshift 3\nexec \"$@\"\n",
    );
    World { dir, db }
}

impl World {
    /// The real program, on this world's database.
    fn program(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_bf-control"))
            .args(args)
            .env("BC_DB", &self.db)
            .output()
            .expect("the program starts")
    }

    /// An account that is an admin, as `admin grant` leaves it.
    fn with_admin(self) -> Self {
        assert_eq!(
            self.program(&["account", "add", "lao"]).status.code(),
            Some(0)
        );
        assert_eq!(
            self.program(&["admin", "grant", "1"]).status.code(),
            Some(0)
        );
        self
    }

    /// The script, with `input` as what is typed (each entry ends with Enter).
    fn run(&self, args: &[&str], input: &str, extra: &[(&str, &str)]) -> Output {
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
            .env("BF_CONTROL", env!("CARGO_BIN_EXE_bf-control"))
            .env("BC_DB", &self.db)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in extra {
            command.env(name, value);
        }
        let mut child = command.spawn().expect("bash starts");
        let mut stdin = child.stdin.take().unwrap();
        // The script may stop before it has read everything; that is not a failure here.
        let _ = stdin.write_all(input.as_bytes());
        drop(stdin);
        child.wait_with_output().unwrap()
    }

    fn stored_hash(&self) -> Option<String> {
        let conn = rusqlite::Connection::open(&self.db).unwrap();
        conn.query_row(
            "SELECT admin_pw_hash FROM accounts WHERE id = 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .unwrap()
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(self.dir.join("ssh_calls")).unwrap_or_default()
    }
}

const GOOD: [&str; 3] = ["1", "root@vm.example", "-o"];

fn good_args() -> Vec<&'static str> {
    vec![GOOD[0], GOOD[1], GOOD[2], "Port=2222"]
}

fn typed(password: &str) -> String {
    format!("{password}\n{password}\n")
}

#[test]
fn the_password_goes_through_one_pipe_into_the_real_command_and_is_never_shown() {
    let world = world("good").with_admin();

    let out = world.run(&good_args(), &typed(PASSWORD), &[]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let shown = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(shown.contains("is set"), "{shown}");
    assert!(!shown.contains(PASSWORD), "never on screen: {shown}");

    // Only a hash is kept, and it is the hash of exactly what was typed.
    let hash = world.stored_hash().expect("the password was stored");
    assert!(hash.starts_with("$argon2id$"), "{hash}");
    assert!(!hash.contains(PASSWORD));
    assert!(verify_password(PASSWORD, &hash));
    assert!(!verify_password("correct horse battery stapl", &hash));

    // The one ssh ran the installed program as the website's user, for this account, with the
    // ssh options before the host; and nothing secret is on any command line.
    let calls = world.calls();
    assert_eq!(
        calls,
        "ssh -o Port=2222 -T root@vm.example runuser -u barely-free -- /usr/local/bin/bf-control admin set-password 1\n",
        "exactly one ssh, the options before the host, -T after them (a remote terminal would \
         echo the password, and a -t or RequestTTY of the person's own must not win), the \
         program run as the website's user"
    );
    assert!(
        !calls.contains(PASSWORD),
        "never on a command line: {calls}"
    );
    let who = std::fs::read_to_string(world.dir.join("runuser_calls")).unwrap();
    assert!(who.contains("-u barely-free --"), "{who}");
    assert!(!who.contains(PASSWORD), "{who}");
    assert_eq!(
        std::fs::read_to_string(world.dir.join("vm_stdin")).unwrap(),
        format!("{PASSWORD}\n"),
        "what the VM was given is the password and one line ending"
    );
}

#[test]
fn spaces_at_the_ends_and_shell_characters_arrive_exactly_as_typed() {
    // A prompt that trims, or that lets the shell look inside the password, would store the
    // hash of something else and lock the admin out with no sign of why.
    for password in [
        "  two spaces both ends  ",
        "it's \"quoted\" and $HOME and `ls` and \\n and * and ; echo hi",
        "tab\tinside the password",
        "ünïcödé pässwörd ✓ ok",
        "-n starts like a flag",
    ] {
        let world = world("exact").with_admin();

        let out = world.run(&good_args(), &typed(password), &[]);

        assert_eq!(
            out.status.code(),
            Some(0),
            "{password:?}: {}",
            text(&out.stderr)
        );
        let hash = world.stored_hash().expect("stored");
        assert!(verify_password(password, &hash), "{password:?}");
    }
}

#[test]
fn two_entries_that_differ_stop_the_script_before_any_ssh() {
    let world = world("differ").with_admin();

    let out = world.run(&good_args(), &format!("{PASSWORD}\n{PASSWORD}x\n"), &[]);

    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains("do not match"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(world.calls(), "", "no ssh was started");
    assert_eq!(world.stored_hash(), None);
    let shown = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(!shown.contains(PASSWORD), "{shown}");
}

#[test]
fn an_empty_entry_or_no_second_entry_stops_the_script_before_any_ssh() {
    for (what, input) in [
        ("nothing typed", ""),
        ("just Enter", "\n\n"),
        ("no confirmation", &format!("{PASSWORD}\n")),
    ] {
        let world = world("empty").with_admin();

        let out = world.run(&good_args(), input, &[]);

        assert_ne!(out.status.code(), Some(0), "{what}");
        assert!(
            !text(&out.stderr).is_empty(),
            "{what}: it says what is wrong"
        );
        assert_eq!(world.calls(), "", "{what}: no ssh was started");
        assert_eq!(world.stored_hash(), None, "{what}");
    }
}

#[test]
fn a_password_the_program_refuses_fails_the_script_and_the_reason_is_shown() {
    let world = world("short").with_admin();

    let out = world.run(&good_args(), &typed("too short"), &[]);

    assert_ne!(out.status.code(), Some(0));
    let shown = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(shown.contains("at least 12 characters"), "{shown}");
    assert!(!shown.contains("is set"), "{shown}");
    assert!(
        shown.contains("not set"),
        "the script says it failed: {shown}"
    );
    assert_eq!(world.stored_hash(), None);
}

#[test]
fn an_account_that_is_not_an_admin_is_refused_by_the_program() {
    let world = world("notadmin");
    assert_eq!(
        world.program(&["account", "add", "lao"]).status.code(),
        Some(0)
    );

    let out = world.run(&good_args(), &typed(PASSWORD), &[]);

    assert_ne!(out.status.code(), Some(0));
    assert_eq!(world.stored_hash(), None, "no password for a non-admin");
    assert!(
        text(&out.stderr).contains("not set"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_connection_that_fails_fails_the_script_and_shows_nothing_secret() {
    let world = world("noconnect").with_admin();

    let out = world.run(&good_args(), &typed(PASSWORD), &[("SSH_FAILS", "1")]);

    assert_ne!(out.status.code(), Some(0));
    let shown = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(!shown.contains(PASSWORD), "{shown}");
    assert!(!shown.contains("is set"), "{shown}");
    assert_eq!(world.stored_hash(), None);
}

#[test]
fn setting_it_again_replaces_the_password() {
    let world = world("again").with_admin();
    assert_eq!(
        world.run(&good_args(), &typed(PASSWORD), &[]).status.code(),
        Some(0)
    );

    let out = world.run(&good_args(), &typed("a different pass phrase"), &[]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let hash = world.stored_hash().unwrap();
    assert!(verify_password("a different pass phrase", &hash));
    assert!(!verify_password(PASSWORD, &hash), "the old one is gone");
}

#[test]
fn a_bad_account_id_or_missing_arguments_stop_it_before_any_ssh() {
    let world = world("badargs").with_admin();
    // The id is put into the command that runs on the VM, so only digits may get there.
    for id in [
        "abc",
        "1; touch /tmp/pwned",
        "$(id)",
        "1 2",
        "-1",
        "",
        "1.5",
        "`id`",
        &"9".repeat(40),
    ] {
        let out = world.run(&[id, GOOD[1]], &typed(PASSWORD), &[]);
        assert_ne!(out.status.code(), Some(0), "{id:?}");
        assert!(
            text(&out.stderr).contains("usage:"),
            "{id:?}: {}",
            text(&out.stderr)
        );
    }
    for args in [&[][..], &["1"]] {
        let out = world.run(args, &typed(PASSWORD), &[]);
        assert_ne!(out.status.code(), Some(0), "{args:?}");
        assert!(
            text(&out.stderr).contains("usage:"),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
    assert_eq!(world.calls(), "", "no ssh was started");
    assert_eq!(world.stored_hash(), None);
}

#[test]
fn the_script_keeps_the_password_off_the_mac_entirely() {
    let source = std::fs::read_to_string(script()).unwrap();

    assert!(
        source.contains("IFS= read -rs"),
        "a hidden prompt that keeps the password as typed"
    );
    assert!(
        source.contains("printf '%s\\n' \"$password\" | ssh"),
        "straight into ssh through a pipe"
    );
    for forbidden in [
        "> /tmp",
        "> \"$TMPDIR",
        "mktemp",
        "echo \"$password",
        "echo $password",
        "password=$(",
        "ssh -t",
        "ssh -tt",
        "--password",
        "set -x",
    ] {
        assert!(!source.contains(forbidden), "{forbidden}");
    }
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

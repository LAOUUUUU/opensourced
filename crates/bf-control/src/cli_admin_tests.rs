//! Tests of `bf-control admin grant | revoke | set-password`, included from `cli.rs`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::adminauth::verify_password;
use crate::poller::HttpsConnector;

const PASSWORD: &str = "a long enough password";

fn db(name: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "bf-cliadmin-{}-{name}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("control.db")
}

/// Runs a command; `typed` is what standard input holds (`None`: nothing connected).
fn run_admin(db: &std::path::Path, typed: Option<&str>, args: &[&str]) -> (u8, String, String) {
    let args: Vec<String> = args.iter().map(ToString::to_string).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let input = typed.map(|text| move || Ok(text.to_string()));
    let context = Context {
        key_file: None,
        nodes_dir: None,
        connector: &HttpsConnector,
        password_input: input
            .as_ref()
            .map(|f| f as &dyn Fn() -> std::io::Result<String>),
    };
    let code = run_in(&args, db, &context, 1_000, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn with_account(name: &str) -> PathBuf {
    let db = db(name);
    assert_eq!(run_admin(&db, None, &["account", "add", "lao"]).0, 0);
    db
}

fn stored_hash(db: &std::path::Path) -> Option<String> {
    Store::open(db)
        .unwrap()
        .conn
        .query_row("SELECT admin_pw_hash FROM accounts WHERE id = 1", [], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn an_account_is_made_an_admin_and_not_one_again_only_from_the_command_line() {
    let db = with_account("grant");
    assert!(!Store::open(&db).unwrap().is_admin(1).unwrap());

    let (code, out, err) = run_admin(&db, None, &["admin", "grant", "1"]);

    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("account 1 (lao)") && out.contains("set-password 1"),
        "{out}"
    );
    assert!(Store::open(&db).unwrap().is_admin(1).unwrap());

    let (code, out, _) = run_admin(&db, None, &["admin", "revoke", "1"]);
    assert_eq!(code, 0);
    assert!(out.contains("no longer an admin"), "{out}");
    assert!(!Store::open(&db).unwrap().is_admin(1).unwrap());
}

#[test]
fn granting_or_revoking_for_an_account_that_is_not_there_is_refused() {
    let db = with_account("missing");
    for verb in ["grant", "revoke"] {
        let (code, _, err) = run_admin(&db, None, &["admin", verb, "9"]);
        assert_eq!(code, 1, "{verb}");
        assert!(err.contains("no account"), "{verb}: {err}");
    }
}

#[test]
fn the_password_is_read_from_standard_input_and_stored_only_as_a_hash() {
    let db = with_account("setpw");
    run_admin(&db, None, &["admin", "grant", "1"]);

    let (code, out, err) = run_admin(
        &db,
        Some(&format!("{PASSWORD}\n")),
        &["admin", "set-password", "1"],
    );

    assert_eq!(code, 0, "{err}");
    assert!(out.contains("is set"), "{out}");
    assert!(!out.contains(PASSWORD) && !err.contains(PASSWORD));
    let hash = stored_hash(&db).unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(
        verify_password(PASSWORD, &hash),
        "the line ending is not part of the password"
    );
    let file = std::fs::read(&db).unwrap();
    assert!(
        !file
            .windows(PASSWORD.len())
            .any(|w| w == PASSWORD.as_bytes()),
        "the password is nowhere in the database"
    );
}

#[test]
fn only_one_line_ending_is_dropped_and_spaces_are_part_of_the_password() {
    for (typed, expected) in [
        ("a password with spaces\r\n", "a password with spaces"),
        ("no line ending at all", "no line ending at all"),
        ("  leading and trailing  \n", "  leading and trailing  "),
        ("two line endings\n\n", "two line endings\n"),
    ] {
        let db = with_account("endings");
        run_admin(&db, None, &["admin", "grant", "1"]);

        let (code, _, err) = run_admin(&db, Some(typed), &["admin", "set-password", "1"]);

        assert_eq!(code, 0, "{typed:?}: {err}");
        assert!(
            verify_password(expected, &stored_hash(&db).unwrap()),
            "{typed:?}"
        );
    }
}

#[test]
fn a_password_that_breaks_a_rule_or_an_account_that_is_not_an_admin_is_refused_with_the_reason_and_the_password_is_never_shown()
 {
    let db = with_account("badpw");
    // Not an admin yet.
    let (code, _, err) = run_admin(&db, Some(PASSWORD), &["admin", "set-password", "1"]);
    assert_eq!(code, 1);
    assert!(
        err.contains("not an admin") && err.contains("admin grant"),
        "{err}"
    );
    assert!(!err.contains(PASSWORD));
    run_admin(&db, None, &["admin", "grant", "1"]);

    for (typed, why) in [
        ("short\n", "at least 12 characters"),
        ("\n", "at least 12 characters"),
        ("", "at least 12 characters"),
        (&format!("{}\n", "x".repeat(300)), "at most 256 bytes"),
    ] {
        let (code, out, err) = run_admin(&db, Some(typed), &["admin", "set-password", "1"]);
        assert_eq!(code, 1, "{why}");
        assert!(err.contains(why), "{why}: {err}");
        assert!(
            !err.contains("short") && !out.contains("short"),
            "the password is not echoed"
        );
    }
    assert_eq!(stored_hash(&db), None, "nothing was stored");

    let (code, _, err) = run_admin(&db, Some(PASSWORD), &["admin", "set-password", "9"]);
    assert_eq!(code, 1);
    assert!(err.contains("no account"), "{err}");
}

#[test]
fn without_standard_input_there_is_no_password_and_nothing_changes() {
    let db = with_account("noinput");
    run_admin(&db, None, &["admin", "grant", "1"]);

    let (code, _, err) = run_admin(&db, None, &["admin", "set-password", "1"]);

    assert_eq!(code, 1);
    assert!(err.contains("standard input"), "{err}");
    assert_eq!(stored_hash(&db), None);
}

#[test]
fn the_password_can_never_be_given_on_the_command_line() {
    let db = with_account("argv");
    run_admin(&db, None, &["admin", "grant", "1"]);

    let (code, _, err) = run_admin(
        &db,
        Some(PASSWORD),
        &["admin", "set-password", "1", PASSWORD],
    );

    assert_eq!(code, 2, "{err}");
    assert_eq!(stored_hash(&db), None);
    assert!(!err.contains(PASSWORD));
}

#[test]
fn revoking_forgets_the_password() {
    let db = with_account("revokepw");
    run_admin(&db, None, &["admin", "grant", "1"]);
    run_admin(&db, Some(PASSWORD), &["admin", "set-password", "1"]);
    assert!(stored_hash(&db).is_some());

    run_admin(&db, None, &["admin", "revoke", "1"]);

    assert_eq!(stored_hash(&db), None);
}

#[test]
fn badly_formed_admin_commands_print_the_usage() {
    let db = with_account("usage");
    for args in [
        &["admin"][..],
        &["admin", "grant"],
        &["admin", "grant", "x"],
        &["admin", "grant", "0"],
        &["admin", "grant", "-1"],
        &["admin", "grant", "1", "2"],
        &["admin", "revoke"],
        &["admin", "set-password"],
        &["admin", "promote", "1"],
    ] {
        let (code, _, err) = run_admin(&db, Some(PASSWORD), args);
        assert_eq!(code, 2, "{args:?}");
        assert!(
            err.contains("admin grant") && err.contains("set-password"),
            "{args:?}"
        );
    }
    assert!(!Store::open(&db).unwrap().is_admin(1).unwrap());
}

// ---- reading the password from standard input ----

/// A reader that fails the test if anything reads it.
struct MustNotBeRead;

impl std::io::Read for MustNotBeRead {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        panic!("standard input was read although it is a terminal");
    }
}

#[test]
fn a_terminal_is_refused_before_anything_is_read_so_the_password_is_never_echoed() {
    // Typed at a terminal, the password would show on the screen and in the scrollback.
    let error = read_password_input(&mut MustNotBeRead, true).unwrap_err();

    let message = error.to_string();
    assert!(message.contains("standard input"), "{message}");
    assert!(
        message.contains("deploy/set-admin-password.sh"),
        "it says what to use instead: {message}"
    );
}

#[test]
fn a_piped_password_is_read_whole_and_at_most_a_kibibyte_of_it() {
    let text = |bytes: &[u8]| read_password_input(&mut &bytes[..], false);

    assert_eq!(text(b"pass phrase here\n").unwrap(), "pass phrase here\n");
    assert_eq!(
        text(b"").unwrap(),
        "",
        "nothing is nothing, not an error here"
    );
    assert_eq!(text(&[b'a'; 1024]).unwrap().len(), 1024);
    let long = text(&[b'a'; 1025]).unwrap_err();
    assert!(long.to_string().contains("far too long"), "{long}");
    assert!(
        text(&[0xff, 0xfe, b'a']).is_err(),
        "bytes that are not text are not a password"
    );
}

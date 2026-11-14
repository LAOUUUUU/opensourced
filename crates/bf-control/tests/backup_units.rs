//! Pins `deploy/bf-backup.service` and `deploy/bf-backup.timer`, which no other test reads:
//! the backup runs as the website's user, inside the website's sandbox, may write only the
//! state folder, keeps its plain copies in a private runtime folder, and runs every night,
//! catching up after a night the VM was off. Spec: `specs/backup.md`.

use std::path::Path;

fn read(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy")
            .join(name),
    )
    .unwrap_or_else(|e| panic!("deploy/{name}: {e}"))
}

/// The values of every uncommented `key=` line, in file order.
fn values(text: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key}=");
    text.lines()
        .filter_map(|line| line.trim().strip_prefix(&prefix).map(str::to_string))
        .collect()
}

fn one(text: &str, key: &str) -> String {
    let found = values(text, key);
    assert_eq!(found.len(), 1, "{key}= should be set once, found {found:?}");
    found[0].clone()
}

#[test]
fn the_backup_runs_once_as_the_website_user_with_its_own_private_runtime_folder() {
    let unit = read("bf-backup.service");
    assert_eq!(one(&unit, "Type"), "oneshot");
    assert_eq!(
        one(&unit, "ExecStart"),
        "/usr/local/lib/barely-free/bf-backup.sh"
    );
    assert_eq!(one(&unit, "User"), "barely-free");
    assert_eq!(one(&unit, "Group"), "barely-free");
    assert_eq!(one(&unit, "RuntimeDirectory"), "bf-backup");
    assert_eq!(one(&unit, "RuntimeDirectoryMode"), "0700");
    assert_eq!(one(&unit, "UMask"), "0077");
    assert_eq!(one(&unit, "ProtectSystem"), "strict");
    assert_eq!(one(&unit, "ReadWritePaths"), "/var/lib/barely-free");
}

#[test]
fn the_backup_reads_the_same_database_and_key_as_the_website() {
    let backup = values(&read("bf-backup.service"), "Environment");
    let website = values(&read("bf-control.service"), "Environment");
    let key = |all: &[String]| {
        all.iter()
            .find(|v| v.starts_with("BC_KEY_FILE="))
            .cloned()
            .unwrap()
    };
    assert_eq!(key(&backup), key(&website));
    assert!(
        backup.contains(&"BC_DB=/var/lib/barely-free/control.db".to_string()),
        "{backup:?}"
    );
}

#[test]
fn the_backup_keeps_every_sandbox_setting_of_the_website() {
    let backup = read("bf-backup.service");
    let website = read("bf-control.service");
    for key in [
        "CapabilityBoundingSet",
        "AmbientCapabilities",
        "NoNewPrivileges",
        "ProtectHome",
        "PrivateTmp",
        "PrivateDevices",
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectKernelLogs",
        "ProtectControlGroups",
        "ProtectClock",
        "ProtectHostname",
        "RestrictNamespaces",
        "RestrictRealtime",
        "RestrictSUIDSGID",
        "LockPersonality",
        "MemoryDenyWriteExecute",
        "SystemCallArchitectures",
        "SystemCallFilter",
        "IPAddressDeny",
    ] {
        assert_eq!(
            values(&backup, key),
            values(&website, key),
            "{key} differs from the website's"
        );
    }
}

#[test]
fn the_timer_runs_nightly_with_a_spread_and_catches_up_a_missed_night() {
    let timer = read("bf-backup.timer");
    assert_eq!(one(&timer, "OnCalendar"), "*-*-* 08:30:00 UTC");
    assert_eq!(one(&timer, "RandomizedDelaySec"), "30min");
    assert_eq!(one(&timer, "Persistent"), "true");
    assert_eq!(one(&timer, "WantedBy"), "timers.target");
}

#[test]
fn the_program_and_the_script_agree_on_where_the_status_is() {
    let script = read("bf-backup.sh");
    let line = format!(
        "status=${{BACKUP_STATUS:-{}}}",
        bf_control::backup::STATUS_FILE
    );
    assert!(script.contains(&line), "deploy/bf-backup.sh has no {line}");
}

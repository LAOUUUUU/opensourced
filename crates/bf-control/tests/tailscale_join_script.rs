//! Runs the real `deploy/tailscale-join.sh` with a stand-in `ssh` that runs the server part
//! here, against a folder standing in for the server, with stand-ins for `apt-get`,
//! `systemctl` and `tailscale`. The key is typed on standard input, as the hidden prompt
//! would read it. Brief: `research/tailscale-ssh/RESEARCH.md`, decision 024.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const KEY: &str = "tskey-auth-kTEST1CNTRL-abcdefGHIJKLmnopqrSTUVWXyz0123456789";

fn deploy(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy")
        .join(name)
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

struct World {
    dir: PathBuf,
}

impl World {
    fn new(name: &str, codename: &str, installed: bool) -> World {
        let dir = std::env::temp_dir().join(format!("bf-tsjoin-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in [
            "bin",
            "node/run",
            "node/etc/apt/sources.list.d",
            "node/usr/share",
        ] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        std::fs::write(
            dir.join("node/etc/os-release"),
            format!("PRETTY_NAME=\"Debian GNU/Linux\"\nVERSION_CODENAME={codename}\n"),
        )
        .unwrap();
        // The server: every absolute path the server part uses is moved under node/.
        executable(
            &dir.join("bin/ssh"),
            r#"#!/bin/bash
printf '%s\n' "$@" > "$RECORD/ssh_args_$RANDOM"
command=${!#}
move() { sed -e "s#/run/#$RECORD/node/run/#g" -e "s#/etc/#$RECORD/node/etc/#g" -e "s#/usr/share/#$RECORD/node/usr/share/#g"; }
command=$(printf '%s' "$command" | move)
move | bash -c "$command"
"#,
        );
        let tailscale = r#"#!/bin/bash
echo "tailscale $*" >> "$RECORD/calls"
case "$1" in
  up)
    for arg in "$@"; do case "$arg" in --auth-key=file:*) f=${arg#--auth-key=file:} ;; esac; done
    [ -n "$f" ] || { echo "no key file" >&2; exit 1; }
    stat -f %Lp "$f" > "$RECORD/key_mode" 2>/dev/null || stat -c %a "$f" > "$RECORD/key_mode"
    cat "$f" > "$RECORD/joined_key"
    echo "$f" > "$RECORD/key_path"
    [ -z "$UP_FAILS" ] || { echo "backend error: invalid key" >&2; exit 1; } ;;
  ip) echo 100.101.102.103 ;;
  *) echo "unexpected tailscale $*" >&2; exit 9 ;;
esac
"#;
        std::fs::write(dir.join("tailscale.template"), tailscale).unwrap();
        if installed {
            executable(&dir.join("bin/tailscale"), tailscale);
        }
        executable(
            &dir.join("bin/apt-get"),
            r#"#!/bin/bash
echo "apt-get $*" >> "$RECORD/calls"
case "$*" in
  *install*tailscale*) cp "$RECORD/tailscale.template" "$RECORD/bin/tailscale"; chmod 755 "$RECORD/bin/tailscale" ;;
esac
"#,
        );
        executable(
            &dir.join("bin/systemctl"),
            "#!/bin/bash\necho \"systemctl $*\" >> \"$RECORD/calls\"\n",
        );
        World { dir }
    }

    fn run(&self, args: &[&str], typed: &str, env: &[(&str, &str)]) -> Output {
        // Only the stand-ins and the system's own folders: a real `tailscale` on the machine
        // running the tests (on the admin's Mac, /usr/local/bin/tailscale) must never be reached,
        // or a test would run `tailscale up` against that machine's own Tailscale.
        const SYSTEM: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
        for dir in SYSTEM {
            for tool in ["tailscale", "tailscaled", "apt-get", "systemctl"] {
                assert!(
                    !Path::new(dir).join(tool).exists(),
                    "refusing to run: a real {tool} is in {dir}"
                );
            }
        }
        let path = format!("{}:{}", self.dir.join("bin").display(), SYSTEM.join(":"));
        let mut command = Command::new("bash");
        command
            .arg(deploy("tailscale-join.sh"))
            .args(args)
            .env("PATH", path)
            .env("RECORD", &self.dir)
            .env("UP_FAILS", "")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command.spawn().unwrap();
        use std::io::Write;
        let _ = child.stdin.take().unwrap().write_all(typed.as_bytes());
        child.wait_with_output().unwrap()
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join(name)).unwrap_or_default()
    }

    fn ssh_args(&self) -> String {
        std::fs::read_dir(&self.dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("ssh_args_")
            })
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect()
    }

    fn run_files(&self) -> Vec<String> {
        std::fs::read_dir(self.dir.join("node/run"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }
}

fn all_output(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn it_installs_tailscale_from_the_pinned_repository_and_joins_with_the_key_from_a_file() {
    let world = World::new("join", "trixie", false);
    let out = world.run(
        &[
            "dallas",
            "root@192.0.2.7",
            "-i",
            "key",
            "-o",
            "IdentitiesOnly=yes",
        ],
        &format!("{KEY}\n"),
        &[],
    );
    let said = all_output(&out);
    assert!(out.status.success(), "{said}");

    // The key reached the server intact, in a file only root could read, never in an
    // argument or in anything printed, and the file is gone.
    assert_eq!(world.read("joined_key").trim_end(), KEY);
    assert_eq!(world.read("key_mode").trim(), "600");
    assert!(
        !said.contains(KEY) && !said.contains("kTEST1CNTRL"),
        "{said}"
    );
    assert!(!world.ssh_args().contains("tskey"), "{}", world.ssh_args());
    assert!(
        !world.read("calls").contains("tskey"),
        "{}",
        world.read("calls")
    );
    assert!(world.run_files().is_empty(), "{:?}", world.run_files());
    assert!(
        world.read("key_path").contains("/node/run/"),
        "kept in /run"
    );

    // Installed from Tailscale's stable repository for trixie, with the key in the repo.
    let list = world.read("node/etc/apt/sources.list.d/tailscale.list");
    let keyring = format!(
        "{}/node/usr/share/keyrings/tailscale-archive-keyring.gpg",
        world.dir.display()
    );
    assert_eq!(
        list,
        format!("deb [signed-by={keyring}] https://pkgs.tailscale.com/stable/debian trixie main\n")
    );
    assert_eq!(
        std::fs::read(&keyring).unwrap(),
        std::fs::read(deploy("tailscale-archive-keyring.gpg")).unwrap(),
        "the keyring checked into the repo"
    );
    let calls = world.read("calls");
    assert!(calls.contains("apt-get install -y tailscale"), "{calls}");
    assert!(
        calls.contains("systemctl enable --now tailscaled"),
        "{calls}"
    );

    // Normal OpenSSH stays the way in: no Tailscale SSH, and the server's DNS is left alone.
    let up = calls
        .lines()
        .find(|line| line.starts_with("tailscale up"))
        .unwrap();
    let args: Vec<&str> = up.split_whitespace().collect();
    assert!(args.contains(&"--hostname=dallas"), "{up}");
    assert!(args.contains(&"--accept-dns=false"), "{up}");
    assert!(!up.contains("--ssh"), "{up}");
    assert!(
        said.contains("dallas joined the tailnet: 100.101.102.103"),
        "{said}"
    );

    // The ssh options were passed through.
    assert!(world.ssh_args().contains("IdentitiesOnly=yes"));
}

#[test]
fn an_installed_tailscale_is_not_installed_again() {
    let world = World::new("installed", "trixie", true);
    let out = world.run(&["toronto", "root@192.0.2.8"], &format!("{KEY}\n"), &[]);
    assert!(out.status.success(), "{}", all_output(&out));
    let calls = world.read("calls");
    assert!(!calls.contains("apt-get"), "{calls}");
    assert!(calls.contains("tailscale up"), "{calls}");
}

#[test]
fn a_key_that_is_not_a_tailscale_auth_key_is_refused_before_anything_is_sent() {
    for typed in [
        "",
        "tskey-api-kAPI1CNTRL-secretsecret\n",
        "tskey-auth-has space\n",
        "hunter2\n",
    ] {
        let world = World::new("badkey", "trixie", false);
        let out = world.run(&["dallas", "root@192.0.2.7"], typed, &[]);
        let said = all_output(&out);
        assert!(!out.status.success(), "{typed:?}");
        assert!(world.ssh_args().is_empty(), "nothing sent for {typed:?}");
        let secret = typed.trim();
        assert!(secret.is_empty() || !said.contains(secret), "{said}");
    }
}

#[test]
fn a_bad_name_or_no_host_is_a_usage_error() {
    for args in [
        &[][..],
        &["dallas"][..],
        &["Dallas!", "root@192.0.2.7"][..],
        &["-x", "root@192.0.2.7"][..],
        &["a;b", "root@192.0.2.7"][..],
    ] {
        let world = World::new("usage", "trixie", false);
        let out = world.run(args, &format!("{KEY}\n"), &[]);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", all_output(&out));
        assert!(world.ssh_args().is_empty(), "{args:?}");
    }
}

#[test]
fn another_debian_release_or_a_failed_join_stops_and_leaves_no_key_behind() {
    let world = World::new("bookworm", "bookworm", false);
    let out = world.run(&["dallas", "root@192.0.2.7"], &format!("{KEY}\n"), &[]);
    assert!(!out.status.success());
    assert!(all_output(&out).contains("trixie"), "{}", all_output(&out));
    assert!(!world.read("calls").contains("apt-get"));
    assert!(world.run_files().is_empty(), "{:?}", world.run_files());

    let world = World::new("upfails", "trixie", true);
    let out = world.run(
        &["dallas", "root@192.0.2.7"],
        &format!("{KEY}\n"),
        &[("UP_FAILS", "1")],
    );
    assert!(!out.status.success());
    assert!(!all_output(&out).contains(KEY));
    assert!(world.run_files().is_empty(), "{:?}", world.run_files());
}

/// The policy to paste into Tailscale's admin console, as JSON: its comments and trailing
/// commas (HuJSON) taken out.
fn policy() -> serde_json::Value {
    let text = std::fs::read_to_string(deploy("tailscale-policy.hujson")).unwrap();
    let json: String = text
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n");
    let json = regex_free_trailing_commas(&json);
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}: {json}"))
}

/// `,` followed only by blanks before a closing bracket is a HuJSON trailing comma.
fn regex_free_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        if *c == ',' {
            let next = chars[i + 1..].iter().find(|c| !c.is_whitespace());
            if matches!(next, Some('}') | Some(']')) {
                continue;
            }
        }
        out.push(*c);
    }
    out
}

#[test]
fn the_policy_lets_lao_reach_the_servers_on_ssh_only_and_the_vm_reach_the_nodes_for_backups() {
    let policy = policy();
    assert!(policy.get("ssh").is_none(), "Tailscale SSH stays off");
    assert!(policy.get("acls").is_none(), "grants only");
    let owners = &policy["tagOwners"];
    assert_eq!(owners["tag:node"], serde_json::json!(["autogroup:admin"]));
    assert_eq!(owners["tag:web"], serde_json::json!(["autogroup:admin"]));
    let grants = policy["grants"].as_array().unwrap();
    let to_servers: Vec<&serde_json::Value> = grants
        .iter()
        .filter(|g| {
            g["dst"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d.as_str().unwrap().starts_with("tag:"))
        })
        .collect();
    assert_eq!(to_servers.len(), 2, "{grants:?}");
    for grant in &to_servers {
        assert_eq!(
            grant["ip"],
            serde_json::json!(["tcp:22"]),
            "only SSH: {grant}"
        );
    }
    assert!(
        to_servers
            .iter()
            .any(|g| g["src"] == serde_json::json!(["tag:web"])
                && g["dst"] == serde_json::json!(["tag:node"])),
        "the VM's backups reach the nodes, and no server reaches the VM"
    );
    for grant in grants {
        let src = grant["src"].as_array().unwrap();
        assert!(
            !src.iter().any(|s| s == "tag:node"),
            "a VPN server reaches nothing: {grant}"
        );
        assert!(
            !src.iter().any(|s| s == "*"),
            "no rule for everyone: {grant}"
        );
    }
    let script = std::fs::read_to_string(deploy("tailscale-join.sh")).unwrap();
    assert!(
        script.contains("tag:node") && script.contains("tag:web"),
        "the join script tells which tag each key carries"
    );
}

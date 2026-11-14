//! SSH logins as the servers' journals record them, for the alert when someone logs in from
//! somewhere new (`specs/login-alerts.md`).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// One successful SSH login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    /// Unix seconds, from the journal line.
    pub at: u64,
    pub user: String,
    /// The address it came from, in full (this is about the admin's own logins).
    pub from: IpAddr,
    /// `SHA256:<fingerprint>` of the key, or `None` for a password login.
    pub key: Option<String>,
    /// The comment of the matching line in `authorized_keys`, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
}

/// A login from one line of `journalctl -o short-unix`:
/// `<unix seconds> <host> <ident>[<pid>]: Accepted <publickey|password> for <user> from <ip>
/// port <n> ssh2[: <TYPE> SHA256:<fp>]`. Anything else is `None`.
pub fn parse_line(line: &str) -> Option<Login> {
    let (stamp, rest) = line.split_once(' ')?;
    let at = stamp.split('.').next()?.parse::<u64>().ok()?;
    let (_, message) = rest.split_once(": ")?;
    let (method, rest) = message.strip_prefix("Accepted ")?.split_once(" for ")?;
    if method != "publickey" && method != "password" {
        return None;
    }
    let (user, rest) = rest.split_once(" from ")?;
    if user.is_empty() || user.contains(char::is_whitespace) {
        return None;
    }
    let (address, rest) = rest.split_once(" port ")?;
    let from = address.parse::<IpAddr>().ok()?.to_canonical();
    let key = match method {
        "publickey" => Some(
            rest.split_whitespace()
                .find(|word| word.starts_with("SHA256:"))?
                .to_string(),
        ),
        _ => None,
    };
    Some(Login {
        at,
        user: user.to_string(),
        from,
        key,
        key_name: None,
    })
}

/// The network a login came from: the address with the last octet zeroed (IPv4, a /24), or
/// its first three groups (IPv6, a /48).
pub fn network(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!(
                "{}/48",
                std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0)
            )
        }
    }
}

/// Where each server's root timer (`deploy/bf-logins.sh`, run by `bf-logins.timer`) writes
/// its recent logins for the agents, or on the VM for the website; group `bf-logins` reads it.
pub const DIR: &str = "/var/lib/barely-free-logins";
/// The `Accepted` journal lines of the last [`WINDOW_SECS`], `-o short-unix`.
pub const LOGINS_FILE: &str = "logins";
/// `ssh-keygen -lf` of root's and each home's `authorized_keys`, which name the keys.
pub const KEYS_FILE: &str = "login-keys";
/// How far back the logins go.
pub const WINDOW_SECS: u64 = 900;
/// A logins file older than this says nothing: its timer has stopped.
pub const STALE_SECS: u64 = 300;

/// Fingerprint to key name, from `ssh-keygen -lf` lines: `<bits> SHA256:<fp> <comment…>
/// (<TYPE>)`. A key with no comment is left out.
pub fn names_from_keygen(text: &str) -> std::collections::HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let fp = words.get(1).filter(|w| w.starts_with("SHA256:"))?;
            let end = if words.last().is_some_and(|w| w.starts_with('(')) {
                words.len() - 1
            } else {
                words.len()
            };
            let name = words.get(2..end).unwrap_or_default().join(" ");
            (!name.is_empty()).then(|| (fp.to_string(), name))
        })
        .collect()
}

/// The logins in a logins file written at `written`, named from its keys file, as of `now`:
/// those of the last [`WINDOW_SECS`]. A file older than [`STALE_SECS`] is an error.
pub fn from_files(logins: &str, keys: &str, written: u64, now: u64) -> Result<Vec<Login>, String> {
    if now.saturating_sub(written) > STALE_SECS {
        return Err(format!(
            "the logins file is older than {STALE_SECS} s (is bf-logins.timer running?)"
        ));
    }
    let names = names_from_keygen(keys);
    let since = now.saturating_sub(WINDOW_SECS);
    Ok(logins
        .lines()
        .filter_map(parse_line)
        .filter(|login| login.at >= since)
        .map(|mut login| {
            login.key_name = login.key.as_ref().and_then(|key| names.get(key)).cloned();
            login
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `ssh-keygen -lf` printed for a test key (made 2026-11-12, private half deleted).
    const KEY_FP: &str = "SHA256:HvjXAIbzUdF23SQNP93/235ibkdyPOxPOROYgxD3Tjs";

    #[test]
    fn a_key_login_line_is_read_with_its_time_user_address_and_key() {
        let line = "1794510662.376535 vps157535-ue9 sshd-session[123807]: Accepted publickey for root from 203.0.113.7 port 54635 ssh2: ED25519 SHA256:HvjXAIbzUdF23SQNP93/235ibkdyPOxPOROYgxD3Tjs";
        assert_eq!(
            parse_line(line),
            Some(Login {
                at: 1_794_510_662,
                user: "root".to_string(),
                from: "203.0.113.7".parse().unwrap(),
                key: Some(KEY_FP.to_string()),
                key_name: None,
            })
        );
    }

    #[test]
    fn a_password_login_has_no_key_and_ipv6_and_odd_user_names_are_read() {
        let line = "1794510700.1 lao sshd[764]: Accepted password for bf-backup.x from 2001:db8:1:2::5 port 59874 ssh2";
        let login = parse_line(line).unwrap();
        assert_eq!(login.user, "bf-backup.x");
        assert_eq!(login.from, "2001:db8:1:2::5".parse::<IpAddr>().unwrap());
        assert_eq!(login.key, None);
        let mapped = "1794510700.1 h sshd[1]: Accepted publickey for root from ::ffff:198.51.100.9 port 1 ssh2: RSA SHA256:abc";
        assert_eq!(
            parse_line(mapped).unwrap().from,
            "198.51.100.9".parse::<IpAddr>().unwrap(),
            "an IPv4 address is written plainly"
        );
    }

    #[test]
    fn anything_but_an_accepted_login_is_not_a_login() {
        for line in [
            "1794510700.1 h sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2",
            "1794510700.1 h sshd[1]: Invalid user admin from 203.0.113.7 port 1",
            "1794510700.1 h sshd[1]: Connection closed by 203.0.113.7 port 1 [preauth]",
            "1794510700.1 h sshd[1]: Accepted publickey for root",
            "1794510700.1 h sshd[1]: Accepted publickey for root from not-an-ip port 1 ssh2",
            "soon h sshd[1]: Accepted password for root from 203.0.113.7 port 1 ssh2",
            "",
            "garbage",
        ] {
            assert_eq!(parse_line(line), None, "{line:?}");
        }
    }

    #[test]
    fn the_network_is_a_slash_24_or_a_slash_48() {
        assert_eq!(network("203.0.113.7".parse().unwrap()), "203.0.113.0/24");
        assert_eq!(
            network("2001:db8:1:2::5".parse().unwrap()),
            "2001:db8:1::/48"
        );
    }

    #[test]
    fn key_names_come_from_ssh_keygen_lines_and_a_key_without_a_comment_has_none() {
        let names = names_from_keygen(&format!(
            "256 {KEY_FP} lao mac key (ED25519)\n\
             3072 SHA256:abc (RSA)\n\
             garbage\n\
             /root/.ssh/authorized_keys is not a public key file.\n"
        ));
        assert_eq!(names.len(), 1, "{names:?}");
        assert_eq!(names.get(KEY_FP).map(String::as_str), Some("lao mac key"));
    }

    #[test]
    fn the_files_give_the_window_s_logins_named_and_a_stale_file_is_an_error() {
        let now = 1_794_510_900;
        let logins = format!(
            "{}.1 h sshd-session[1]: Accepted publickey for root from 203.0.113.7 port 1 ssh2: ED25519 {KEY_FP}\n\
             {}.1 h sshd-session[2]: Accepted password for root from 203.0.113.8 port 1 ssh2\n\
             {}.1 h sshd-session[3]: Accepted publickey for root from 203.0.113.9 port 1 ssh2: RSA SHA256:other\n",
            now - 60,
            now - WINDOW_SECS - 1,
            now - 30
        );
        let keys = format!("256 {KEY_FP} lao-mac (ED25519)\n");
        let read = from_files(&logins, &keys, now - 20, now).unwrap();
        assert_eq!(read.len(), 2, "inside the window only: {read:?}");
        assert_eq!(read[0].key_name.as_deref(), Some("lao-mac"));
        assert_eq!(read[1].key_name, None, "a key not in authorized_keys");
        let stale = from_files(&logins, &keys, now - STALE_SECS - 1, now).unwrap_err();
        assert!(stale.contains("older than"), "{stale}");
        assert!(
            from_files("", "", now - STALE_SECS, now)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_login_round_trips_as_json_and_an_unknown_key_name_is_left_out() {
        let login = parse_line(
            "1794510700.1 h sshd[1]: Accepted password for root from 203.0.113.7 port 1 ssh2",
        )
        .unwrap();
        let json = serde_json::to_string(&login).unwrap();
        assert!(!json.contains("key_name"), "{json}");
        assert_eq!(serde_json::from_str::<Login>(&json).unwrap(), login);
    }
}

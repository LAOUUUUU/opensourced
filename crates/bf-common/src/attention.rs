//! What on a server needs Lao's attention (`research/needs-attention/RESEARCH.md`,
//! decision 031): a reboot it asked for, and package updates waiting. A root timer,
//! `bf-attention.timer`, writes them once an hour into the folder the agents may already read
//! (`crate::logins::DIR`, group `bf-logins`); the agent reads the file into its signed status
//! and the website shows it in the admin overview. Nothing here is about users.

use serde::{Deserialize, Serialize};

/// The file the timer writes, in `crate::logins::DIR`.
pub const FILE: &str = "attention";
/// A file older than this (three missed hourly runs) is not reported: it says nothing now.
pub const STALE_SECS: u64 = 3 * 3600;
/// At most this many packages are kept (reboot and waiting together).
pub const MAX_ITEMS: usize = 50;

/// What needs attention on one server. The default is "nothing".
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Attention {
    /// Whether the server asked for a reboot (`/run/reboot-required`).
    pub reboot: bool,
    /// The packages that asked for it, when the flag names them.
    #[serde(default)]
    pub reboot_by: Vec<String>,
    /// Package updates waiting: the name and the version that would be installed.
    #[serde(default)]
    pub waiting: Vec<Waiting>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiting {
    pub name: String,
    pub version: String,
}

impl Attention {
    /// Whether there is anything to show.
    pub fn is_empty(&self) -> bool {
        !self.reboot && self.waiting.is_empty()
    }

    /// The same, keeping only package names and versions that look like Debian's and at most
    /// [`MAX_ITEMS`] of them, so it is safe to print in a page.
    pub fn sanitized(self) -> Attention {
        let mut room = MAX_ITEMS;
        let mut keep = |ok: bool| {
            let kept = ok && room > 0;
            room -= usize::from(kept);
            kept
        };
        let reboot_by = self
            .reboot_by
            .into_iter()
            .filter(|name| keep(safe_name(name)))
            .collect();
        let waiting = self
            .waiting
            .into_iter()
            .filter(|w| keep(safe_name(&w.name) && safe_version(&w.version)))
            .collect();
        Attention {
            reboot: self.reboot,
            reboot_by,
            waiting,
        }
    }
}

/// A Debian package name: a lower-case letter or digit, then letters, digits, `+`, `-` and
/// `.`, 2 to 100 characters.
pub fn safe_name(name: &str) -> bool {
    let mut chars = name.chars();
    (2..=100).contains(&name.len())
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c))
}

/// A Debian package version: letters, digits and `.+~:-`, 1 to 100 characters.
pub fn safe_version(version: &str) -> bool {
    (1..=100).contains(&version.len())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+~:-".contains(c))
}

/// Reads the timer's file, written at `written` (Unix seconds), as of `now`: `reboot` or
/// `reboot <package>` lines and `waiting <package> <version>` lines. Anything else, and any
/// name or version that does not look like Debian's, is skipped. An old file is an error.
pub fn from_file(text: &str, written: u64, now: u64) -> Result<Attention, String> {
    let age = now.saturating_sub(written);
    if age > STALE_SECS {
        return Err(format!("the attention file is {} minutes old", age / 60));
    }
    let mut found = Attention::default();
    for line in text.lines() {
        match line.split_whitespace().collect::<Vec<_>>()[..] {
            ["reboot"] => found.reboot = true,
            ["reboot", name] => {
                found.reboot = true;
                found.reboot_by.push(name.to_string());
            }
            ["waiting", name, version] => found.waiting.push(Waiting {
                name: name.to_string(),
                version: version.to_string(),
            }),
            _ => {}
        }
    }
    Ok(found.sanitized())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn a_clean_server_needs_nothing() {
        let a = from_file("", NOW - 60, NOW).unwrap();
        assert!(a.is_empty());
        assert_eq!(a, Attention::default());
    }

    #[test]
    fn the_reboot_flag_with_its_packages_and_the_updates_waiting_are_read() {
        let text = "reboot linux-image-6.12.117+deb13-amd64\nreboot amneziawg-dkms\n\
                    waiting amneziawg-dkms 1.0.0-0~202611131431+63ed35d~ubuntu20.04.1\n\
                    waiting libc6 2.41-12+deb13u1\n";
        let a = from_file(text, NOW - 60, NOW).unwrap();
        assert!(a.reboot);
        assert_eq!(
            a.reboot_by,
            ["linux-image-6.12.117+deb13-amd64", "amneziawg-dkms"]
        );
        assert_eq!(
            a.waiting,
            [
                Waiting {
                    name: "amneziawg-dkms".into(),
                    version: "1.0.0-0~202611131431+63ed35d~ubuntu20.04.1".into()
                },
                Waiting {
                    name: "libc6".into(),
                    version: "2.41-12+deb13u1".into()
                },
            ]
        );
        assert!(!a.is_empty());
    }

    #[test]
    fn a_reboot_flag_that_names_nothing_still_counts() {
        let a = from_file("reboot\n", NOW - 60, NOW).unwrap();
        assert!(a.reboot);
        assert!(a.reboot_by.is_empty());
    }

    #[test]
    fn lines_and_names_that_do_not_look_right_are_skipped_one_by_one() {
        let text = "reboot <script>\nwaiting libc6\nwaiting Bad_Name 1.0\nwaiting ok-pkg 1.0 extra\n\
                    hello\nwaiting good 1:2.3-4~x+y\nwaiting x 1.0\n";
        let a = from_file(text, NOW - 60, NOW).unwrap();
        assert!(
            a.reboot,
            "a reboot line counts even if its package name is refused"
        );
        assert!(a.reboot_by.is_empty());
        assert_eq!(
            a.waiting,
            [Waiting {
                name: "good".into(),
                version: "1:2.3-4~x+y".into()
            }]
        );
    }

    #[test]
    fn at_most_fifty_packages_are_kept() {
        let text: String = (0..80).map(|i| format!("waiting pkg{i} 1.{i}\n")).collect();
        let a = from_file(&text, NOW - 60, NOW).unwrap();
        assert_eq!(a.waiting.len(), MAX_ITEMS);
        assert_eq!(a.waiting[0].name, "pkg0");
    }

    #[test]
    fn a_file_older_than_three_hours_is_an_error_not_old_news() {
        assert!(from_file("reboot\n", NOW - STALE_SECS, NOW).is_ok());
        let e = from_file("reboot\n", NOW - STALE_SECS - 1, NOW).unwrap_err();
        assert!(e.contains("old"), "{e}");
    }

    #[test]
    fn names_and_versions_are_checked_the_debian_way() {
        for good in ["libc6", "linux-image-6.12.117+deb13-amd64", "g++", "x2"] {
            assert!(safe_name(good), "{good}");
        }
        for bad in ["", "a", "Libc6", "-x", "a b", "a_b", "é", &"a".repeat(101)] {
            assert!(!safe_name(bad), "{bad:?}");
        }
        for good in [
            "1",
            "2.41-12+deb13u1",
            "1:2.3~rc1",
            "1.0.0-0~202611131431+63ed35d",
        ] {
            assert!(safe_version(good), "{good}");
        }
        for bad in ["", "1 2", "1/2", "<1>", &"1".repeat(101)] {
            assert!(!safe_version(bad), "{bad:?}");
        }
    }

    #[test]
    fn what_a_node_sends_is_cleaned_the_same_way_before_it_is_shown() {
        let sent = Attention {
            reboot: true,
            reboot_by: vec!["ok-pkg".into(), "<b>".into()],
            waiting: (0..60)
                .map(|i| Waiting {
                    name: if i == 0 {
                        "Bad".into()
                    } else {
                        format!("p{i}")
                    },
                    version: "1.0".into(),
                })
                .collect(),
        };
        let clean = sent.sanitized();
        assert_eq!(clean.reboot_by, ["ok-pkg"]);
        assert_eq!(clean.waiting.len() + clean.reboot_by.len(), MAX_ITEMS);
        assert_eq!(clean.waiting[0].name, "p1");
    }
}

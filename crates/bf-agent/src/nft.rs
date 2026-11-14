//! The per-device tracker switch on a node (`specs/trackers.md`): an nftables set of the
//! device addresses whose trackers are not blocked. The node's setup script makes the table
//! `inet barely_free_dns`, its sets and the rule that sends port-53 traffic from an address
//! in a set to the resolver's unfiltered port; the agent only ever fills its own set.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::config::TrackerSwitch;
use crate::wgcli::{WgError, run_program};

/// The table the node's setup script makes.
const TABLE: &str = "inet barely_free_dns";

/// `nft` answers in milliseconds; one that hangs must not freeze the agent.
const DEADLINE: Duration = Duration::from_secs(10);

/// What the agent needs from the switch. Tests swap in a fake.
pub trait TrackerSet: Send + Sync {
    /// Makes the set hold exactly `off`, the addresses whose trackers are not blocked.
    fn replace(&self, off: &[Ipv4Addr]) -> Result<(), WgError>;
}

/// The set, changed through the `nft` program.
pub struct NftSet {
    bin: String,
    set: String,
}

impl NftSet {
    pub fn new(switch: &TrackerSwitch) -> NftSet {
        NftSet {
            bin: switch.nft_bin.clone(),
            set: switch.set.clone(),
        }
    }
}

impl TrackerSet for NftSet {
    /// One `nft -f -` run is one transaction: packets see the old set or the new one,
    /// never an empty one in between.
    fn replace(&self, off: &[Ipv4Addr]) -> Result<(), WgError> {
        let mut script = format!("flush set {TABLE} {}\n", self.set);
        if !off.is_empty() {
            let addresses: Vec<String> = off.iter().map(ToString::to_string).collect();
            script.push_str(&format!(
                "add element {TABLE} {} {{ {} }}\n",
                self.set,
                addresses.join(", ")
            ));
        }
        run_program(
            &self.bin,
            "nft",
            &["-f", "-"],
            Some(script.as_bytes()),
            DEADLINE,
        )
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::config::TrackerSwitch;
    use crate::testutil::TempDir;

    /// A fake `nft` that writes its arguments and its standard input to two files.
    fn fake_nft(dir: &TempDir, extra: &str) -> TrackerSwitch {
        let path = dir.path().join("fake-nft");
        let body = format!(
            "#!/bin/sh\necho \"$@\" >> '{args}'\ncat >> '{input}'\n{extra}\n",
            args = dir.path().join("args").display(),
            input = dir.path().join("input").display(),
        );
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        TrackerSwitch {
            nft_bin: path.to_str().unwrap().to_string(),
            set: "off_awg0".to_string(),
        }
    }

    fn read(dir: &TempDir, name: &str) -> String {
        std::fs::read_to_string(dir.path().join(name)).unwrap_or_default()
    }

    #[test]
    fn the_set_is_replaced_whole_in_one_nft_transaction_read_from_standard_input() {
        let dir = TempDir::new("nft");
        let set = NftSet::new(&fake_nft(&dir, ""));

        set.replace(&[Ipv4Addr::new(10, 77, 0, 5), Ipv4Addr::new(10, 77, 0, 9)])
            .unwrap();
        set.replace(&[]).unwrap();

        assert_eq!(read(&dir, "args"), "-f -\n-f -\n");
        assert_eq!(
            read(&dir, "input"),
            "flush set inet barely_free_dns off_awg0\n\
             add element inet barely_free_dns off_awg0 { 10.77.0.5, 10.77.0.9 }\n\
             flush set inet barely_free_dns off_awg0\n"
        );
    }

    #[test]
    fn a_failing_nft_is_an_error_with_the_first_line_it_said() {
        let dir = TempDir::new("nft-fail");
        let set = NftSet::new(&fake_nft(
            &dir,
            "echo 'Error: No such file or directory' >&2\necho 'second' >&2\nexit 1",
        ));

        let err = set.replace(&[Ipv4Addr::new(10, 77, 0, 5)]).unwrap_err();

        assert!(err.0.contains("nft -f failed"), "{err}");
        assert!(err.0.contains("No such file or directory"), "{err}");
        assert!(!err.0.contains("second"), "{err}");
    }
}

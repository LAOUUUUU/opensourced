//! Pins the security choices in `deploy/bf-control.service`, which no other test reads.
//!
//! The service has to reach `api.resend.com` (Resend publishes no fixed addresses, so the
//! unit cannot list them) and the nodes (public addresses). So outbound traffic is not
//! blocked as a whole; what is blocked is everything inside: the VM's own network, its host
//! and the home network behind it, so a flaw in this program cannot be used to reach them.
//! The loopback address stays open because the Cloudflare tunnel comes in over it.

use std::path::Path;

fn unit() -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/bf-control.service"),
    )
    .expect("deploy/bf-control.service")
}

/// Every word on every uncommented `key=` line, in file order.
fn words(key: &str) -> Vec<String> {
    let prefix = format!("{key}=");
    unit()
        .lines()
        .filter_map(|line| line.trim().strip_prefix(&prefix).map(str::to_string))
        .flat_map(|rest| {
            rest.split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn outbound_traffic_cannot_reach_internal_networks() {
    let denied = words("IPAddressDeny");

    for range in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    ] {
        assert!(
            denied.iter().any(|d| d == range),
            "{range} is not denied; IPAddressDeny= has {denied:?}"
        );
    }
}

#[test]
fn the_public_internet_and_this_computer_stay_reachable() {
    let denied = words("IPAddressDeny");

    // Anything that would also cut off Resend, the nodes or the tunnel on loopback.
    for wrong in [
        "any",
        "localhost",
        "0.0.0.0/0",
        "::/0",
        "127.0.0.0/8",
        "127.0.0.1",
        "::1",
    ] {
        assert!(
            !denied.iter().any(|d| d == wrong),
            "{wrong} must not be denied; IPAddressDeny= has {denied:?}"
        );
    }
    // A fixed allow-list would go stale the day Resend moves, and mail would stop.
    assert_eq!(
        words("IPAddressAllow"),
        Vec::<String>::new(),
        "no fixed addresses in the unit"
    );
}

#[test]
fn the_other_hardening_stays() {
    let unit = unit();
    for line in [
        "User=barely-free",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "RestrictAddressFamilies=AF_INET AF_INET6",
        "CapabilityBoundingSet=",
        "MemoryDenyWriteExecute=yes",
        "SystemCallFilter=@system-service",
        "Environment=BC_LISTEN=127.0.0.1:18500",
    ] {
        assert!(
            unit.lines().any(|l| l.trim() == line),
            "{line} is missing from deploy/bf-control.service"
        );
    }
}

#[test]
fn sign_up_is_open() {
    // Lao, 2026-11-12: "make it open now" (decision 010; the caps are in the code).
    assert_eq!(
        words("Environment")
            .iter()
            .filter(|w| *w == "BC_OPEN_SIGNUP=1")
            .count(),
        1
    );
}

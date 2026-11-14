//! Where to get the app for each protocol: the official listings only (checked 2026-11-10,
//! `research/dual-protocol/EXTERNAL.md`). Plain links; nothing is loaded from those sites.

use crate::protocol::Protocol;

/// One platform's official download.
pub struct AppLink {
    pub platform: &'static str,
    pub url: &'static str,
}

/// The app for one protocol, with its downloads.
pub struct AppGroup {
    pub title: &'static str,
    pub links: &'static [AppLink],
    /// Said after the links ("no Linux app"), or empty.
    pub note: &'static str,
}

const WIREGUARD: [AppLink; 5] = [
    AppLink {
        platform: "iPhone and iPad",
        url: "https://apps.apple.com/app/wireguard/id1441195209",
    },
    AppLink {
        platform: "Android",
        url: "https://play.google.com/store/apps/details?id=com.wireguard.android",
    },
    AppLink {
        platform: "Mac",
        url: "https://apps.apple.com/app/wireguard/id1451685025",
    },
    AppLink {
        platform: "Windows",
        url: "https://download.wireguard.com/windows-client/wireguard-installer.exe",
    },
    AppLink {
        platform: "Linux",
        url: "https://www.wireguard.com/install/",
    },
];

const AMNEZIAWG: [AppLink; 3] = [
    AppLink {
        platform: "iPhone, iPad and Mac",
        url: "https://apps.apple.com/app/amneziawg/id6478942365",
    },
    AppLink {
        platform: "Android",
        url: "https://play.google.com/store/apps/details?id=org.amnezia.awg",
    },
    AppLink {
        platform: "Windows",
        url: "https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest",
    },
];

const CLASHMI: [AppLink; 2] = [
    AppLink {
        platform: "iPhone and iPad",
        url: "https://apps.apple.com/app/clash-mi/id6744321968",
    },
    AppLink {
        platform: "Android, Mac, Windows and Linux",
        url: "https://clashmi.app/download",
    },
];

/// ClashMi, the recommended app (decision 019): one profile holds every server and port.
pub fn clashmi() -> AppGroup {
    AppGroup {
        title: "ClashMi",
        links: &CLASHMI,
        note: "Recommended: it switches server and port by itself. Open source, made by KaringX.",
    }
}

/// What the account page lists: ClashMi first, then the official apps.
pub fn for_account() -> Vec<AppGroup> {
    let mut all = vec![clashmi()];
    all.extend(both());
    all
}

/// The app a device of `protocol` needs.
pub fn app_for(protocol: Protocol) -> AppGroup {
    match protocol {
        Protocol::WireGuard => AppGroup {
            title: "WireGuard",
            links: &WIREGUARD,
            note: "",
        },
        Protocol::AmneziaWg => AppGroup {
            title: "AmneziaWG",
            links: &AMNEZIAWG,
            note: "There is no Linux app.",
        },
    }
}

/// Both apps, WireGuard first.
pub fn both() -> Vec<AppGroup> {
    vec![app_for(Protocol::WireGuard), app_for(Protocol::AmneziaWg)]
}

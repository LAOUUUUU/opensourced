//! Signing of the requests between the control program and the agents.
//!
//! The signed text is five lines: method, path with query, time (Unix seconds), nonce,
//! and the hex SHA-256 of the body. The signature is the hex HMAC-SHA256 of that text
//! under the node's secret.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt::Write as _;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Requests whose time is further than this many seconds from the agent's clock are
/// refused.
pub const WINDOW_SECS: u64 = 60;

/// The parts of a request that are signed.
#[derive(Debug, Clone, Copy)]
pub struct Parts<'a> {
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub time: u64,
    pub nonce: &'a str,
    pub body: &'a [u8],
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Reads hex (either case); `None` if the length is odd or a character is not hex.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn signed_text(parts: &Parts<'_>) -> String {
    let body_hash = hex(Sha256::digest(parts.body).as_slice());
    format!(
        "{}\n{}\n{}\n{}\n{}",
        parts.method, parts.path_and_query, parts.time, parts.nonce, body_hash
    )
}

fn mac_for(secret: &[u8], parts: &Parts<'_>) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(signed_text(parts).as_bytes());
    mac
}

pub fn sign(secret: &[u8], parts: &Parts<'_>) -> String {
    hex(mac_for(secret, parts).finalize().into_bytes().as_slice())
}

/// Why a request was refused. The agent answers all of them the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    BadNonce,
    BadSignature,
    OutOfWindow,
    Replay,
    /// Signed at or before the verifier's floor: it could be a copy of a request that was
    /// accepted before the agent restarted.
    BeforeRestart,
}

/// Checks signatures for one node and remembers the nonces it has accepted.
pub struct Verifier {
    secret: Vec<u8>,
    seen: HashMap<String, u64>,
    /// Requests signed at or before this time are refused.
    floor: u64,
    /// The highest time among the requests accepted so far (the floor, before any).
    highest: u64,
}

impl Verifier {
    pub fn new(secret: Vec<u8>) -> Self {
        Self::with_floor(secret, 0)
    }

    /// A verifier that refuses every request signed at or before `floor`.
    ///
    /// The nonces it remembers live in memory, so a restart forgets them and a copy of a
    /// request accepted just before could be accepted again. A request accepted before
    /// has a time at or below the highest time the old process had accepted
    /// ([`Verifier::highest_accepted`], kept on disk by the caller), so using that as the
    /// floor refuses all such copies. Requests signed afterwards are unaffected.
    pub fn with_floor(secret: Vec<u8>, floor: u64) -> Self {
        Self {
            secret,
            seen: HashMap::new(),
            floor,
            highest: floor,
        }
    }

    /// The highest time among the requests this verifier has accepted, or its floor if it
    /// has accepted none. Only a request that passed every check moves it.
    pub fn highest_accepted(&self) -> u64 {
        self.highest
    }

    pub fn verify(
        &mut self,
        now: u64,
        parts: &Parts<'_>,
        signature_hex: &str,
    ) -> Result<(), Refusal> {
        let nonce = parts.nonce;
        if !(16..=128).contains(&nonce.len()) || !nonce.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(Refusal::BadNonce);
        }
        let tag = unhex(signature_hex).ok_or(Refusal::BadSignature)?;
        mac_for(&self.secret, parts)
            .verify_slice(&tag)
            .map_err(|_| Refusal::BadSignature)?;
        if now.abs_diff(parts.time) > WINDOW_SECS {
            return Err(Refusal::OutOfWindow);
        }
        if parts.time <= self.floor {
            return Err(Refusal::BeforeRestart);
        }
        // A nonce only matters while a request carrying it could still be inside the window.
        self.seen.retain(|_, expires| *expires >= now);
        match self.seen.entry(parts.nonce.to_string()) {
            Entry::Occupied(_) => Err(Refusal::Replay),
            Entry::Vacant(slot) => {
                slot.insert(parts.time.saturating_add(WINDOW_SECS));
                self.highest = self.highest.max(parts.time);
                Ok(())
            }
        }
    }

    /// How many accepted nonces are still remembered.
    pub fn remembered(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn secret() -> Vec<u8> {
        unhex(SECRET_HEX).unwrap()
    }

    #[test]
    fn signatures_match_vectors_computed_with_python() {
        let status = Parts {
            method: "GET",
            path_and_query: "/v1/status",
            time: 1_794_280_000,
            nonce: "0123456789abcdef",
            body: b"",
        };
        assert_eq!(
            signed_text(&status),
            "GET\n/v1/status\n1794280000\n0123456789abcdef\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sign(&secret(), &status),
            "bdce41185bcbc4337c054817c54cbded2d663a2e8e5c7fc558d214aee48158e4"
        );

        let put = Parts {
            method: "PUT",
            path_and_query: "/v1/peers?x=1",
            time: 1_794_280_001,
            nonce: "fedcba9876543210",
            body: br#"{"version":1,"peers":[]}"#,
        };
        assert_eq!(
            sign(&secret(), &put),
            "d49c559dd01a2e9b0ca71bd57936a732d3bcd7d8262ecb24c751ecd14406c8de"
        );
    }

    #[test]
    fn hex_round_trips_and_rejects_what_is_not_hex() {
        assert_eq!(hex(&[0, 255, 16]), "00ff10");
        assert_eq!(unhex("00FF10"), Some(vec![0, 255, 16]));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }

    fn request() -> Parts<'static> {
        Parts {
            method: "PUT",
            path_and_query: "/v1/peers",
            time: 1_000,
            nonce: "0123456789abcdef",
            body: b"{}",
        }
    }

    fn verifier() -> Verifier {
        Verifier::new(secret())
    }

    #[test]
    fn a_correct_signature_passes_and_changing_any_signed_part_breaks_it() {
        let ok = request();
        let signature = sign(&secret(), &ok);
        assert_eq!(verifier().verify(1_000, &ok, &signature), Ok(()));

        let changed = [
            Parts {
                method: "GET",
                ..ok
            },
            Parts {
                path_and_query: "/v1/peers?x",
                ..ok
            },
            Parts { time: 1_001, ..ok },
            Parts {
                nonce: "0123456789abcdeX",
                ..ok
            },
            Parts { body: b"{ }", ..ok },
        ];
        for parts in changed {
            assert_eq!(
                verifier().verify(1_000, &parts, &signature),
                Err(Refusal::BadSignature),
                "{parts:?}"
            );
        }

        let from_another_secret = sign(&[7; 32], &ok);
        for bad in [from_another_secret.as_str(), &signature[..62], "zz", ""] {
            assert_eq!(
                verifier().verify(1_000, &ok, bad),
                Err(Refusal::BadSignature),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn requests_further_than_sixty_seconds_from_the_clock_are_refused() {
        let check = |now, time| {
            let parts = Parts { time, ..request() };
            verifier().verify(now, &parts, &sign(&secret(), &parts))
        };

        assert_eq!(check(1_000, 940), Ok(()));
        assert_eq!(check(1_000, 1_060), Ok(()));
        assert_eq!(check(1_000, 939), Err(Refusal::OutOfWindow));
        assert_eq!(check(1_000, 1_061), Err(Refusal::OutOfWindow));
    }

    #[test]
    fn a_nonce_is_good_once_and_a_refused_request_does_not_use_one_up() {
        let mut v = verifier();
        let first = request();
        let first_sig = sign(&secret(), &first);
        assert_eq!(v.verify(1_000, &first, &first_sig), Ok(()));
        assert_eq!(v.verify(1_001, &first, &first_sig), Err(Refusal::Replay));

        // The same nonce on a different, correctly signed request is a replay too.
        let other = Parts {
            method: "GET",
            path_and_query: "/v1/status",
            body: b"",
            ..first
        };
        assert_eq!(
            v.verify(1_001, &other, &sign(&secret(), &other)),
            Err(Refusal::Replay)
        );

        // A request refused for its signature leaves its nonce free for the real one.
        let fresh = Parts {
            nonce: "aaaaaaaaaaaaaaaa",
            ..first
        };
        assert_eq!(
            v.verify(1_001, &fresh, &first_sig),
            Err(Refusal::BadSignature)
        );
        assert_eq!(v.verify(1_001, &fresh, &sign(&secret(), &fresh)), Ok(()));
    }

    #[test]
    fn nonces_are_forgotten_once_their_window_has_passed() {
        let mut v = verifier();
        for i in 0..50 {
            let nonce = format!("nonce-number-{i:04}");
            let parts = Parts {
                nonce: &nonce,
                ..request()
            };
            v.verify(1_000, &parts, &sign(&secret(), &parts)).unwrap();
        }
        assert_eq!(v.remembered(), 50);

        let late = Parts {
            time: 2_000,
            nonce: "late-late-late-late",
            ..request()
        };
        v.verify(2_000, &late, &sign(&secret(), &late)).unwrap();

        assert_eq!(v.remembered(), 1);
    }

    #[test]
    fn a_floor_refuses_every_request_signed_at_or_before_it_and_uses_no_nonce_up() {
        // A request accepted before a restart has a time at or below the highest time the
        // agent had accepted, so a floor set to that time refuses every copy of it.
        let floor = 1_000;
        for (time, expected) in [
            (999, Err(Refusal::BeforeRestart)),
            (1_000, Err(Refusal::BeforeRestart)),
            (1_001, Ok(())),
        ] {
            let parts = Parts { time, ..request() };
            let mut v = Verifier::with_floor(secret(), floor);
            assert_eq!(
                v.verify(1_000, &parts, &sign(&secret(), &parts)),
                expected,
                "time {time}"
            );
        }

        // Being refused for its time leaves the nonce free for a request that is fresh.
        let mut v = Verifier::with_floor(secret(), floor);
        let old = Parts {
            time: 990,
            ..request()
        };
        assert_eq!(
            v.verify(1_000, &old, &sign(&secret(), &old)),
            Err(Refusal::BeforeRestart)
        );
        let fresh = Parts {
            time: 1_005,
            ..request()
        };
        assert_eq!(v.verify(1_005, &fresh, &sign(&secret(), &fresh)), Ok(()));
    }

    #[test]
    fn the_highest_accepted_time_only_moves_for_requests_that_were_accepted() {
        let mut v = Verifier::with_floor(secret(), 500);
        assert_eq!(v.highest_accepted(), 500, "it starts at the floor");
        assert_eq!(Verifier::new(secret()).highest_accepted(), 0);

        let at = |time: u64, nonce: &'static str| Parts {
            time,
            nonce,
            ..request()
        };
        let accept =
            |v: &mut Verifier, parts: &Parts<'_>| v.verify(1_000, parts, &sign(&secret(), parts));

        let first = at(1_000, "nonce-for-time-1000");
        assert_eq!(accept(&mut v, &first), Ok(()));
        assert_eq!(v.highest_accepted(), 1_000);

        // Older but still inside the window: accepted, and the highest stays.
        assert_eq!(accept(&mut v, &at(990, "nonce-for-time-0990")), Ok(()));
        assert_eq!(v.highest_accepted(), 1_000);

        // A replay, a bad signature and a time outside the window change nothing.
        assert_eq!(accept(&mut v, &first), Err(Refusal::Replay));
        let forged = at(1_050, "nonce-for-time-1050");
        assert_eq!(v.verify(1_000, &forged, "00"), Err(Refusal::BadSignature));
        assert_eq!(
            accept(&mut v, &at(5_000, "nonce-for-time-5000")),
            Err(Refusal::OutOfWindow)
        );
        assert_eq!(v.highest_accepted(), 1_000);

        assert_eq!(accept(&mut v, &at(1_040, "nonce-for-time-1040")), Ok(()));
        assert_eq!(v.highest_accepted(), 1_040);
    }

    #[test]
    fn a_nonce_must_be_16_to_128_visible_ascii_characters() {
        let check = |nonce: &str| {
            let parts = Parts { nonce, ..request() };
            verifier().verify(1_000, &parts, &sign(&secret(), &parts))
        };

        assert_eq!(check("0123456789abcdef"), Ok(()));
        assert_eq!(check(&"x".repeat(128)), Ok(()));
        for bad in [
            "",
            "0123456789abcde",
            &"x".repeat(129),
            "0123456789 abcdef",
            "0123456789\nabcdef",
            "0123456789abcdéf",
        ] {
            assert_eq!(check(bad), Err(Refusal::BadNonce), "{bad:?}");
        }
    }
}

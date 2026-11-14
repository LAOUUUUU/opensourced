//! WireGuard key pairs for new devices.
//!
//! A private key is 32 random bytes; the public key is X25519 of it and the base point.
//! Both are written as base64, the way `wg` reads and prints them.

use std::fs::File;
use std::io::Read;

use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

/// A device's keys. The private half is handed to the device's owner once and is never
/// stored, so it is kept out of `Debug` and has no public field.
#[derive(Clone)]
pub struct KeyPair {
    private: [u8; 32],
    pub public_key: String,
}

impl KeyPair {
    /// The pair that belongs to these private key bytes.
    pub fn from_private(private: [u8; 32]) -> KeyPair {
        let public = x25519(private, X25519_BASEPOINT_BYTES);
        KeyPair {
            private,
            public_key: base64(&public),
        }
    }

    /// A new pair from the operating system's random source, clamped the way
    /// `wg genkey` clamps its keys.
    pub fn generate() -> std::io::Result<KeyPair> {
        let mut private = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut private)?;
        private[0] &= 0b1111_1000;
        private[31] = (private[31] & 0b0111_1111) | 0b0100_0000;
        Ok(KeyPair::from_private(private))
    }

    /// The private key as base64, for the device's own configuration.
    pub fn private_key(&self) -> String {
        base64(&self.private)
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// Standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let sextets = [
            b[0] >> 2,
            ((b[0] & 0x03) << 4) | (b[1] >> 4),
            ((b[1] & 0x0f) << 2) | (b[2] >> 6),
            b[2] & 0x3f,
        ];
        for (i, sextet) in sextets.iter().enumerate() {
            if i <= chunk.len() {
                out.push(ALPHABET[usize::from(*sextet)] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bf_common::peers::is_valid_key;

    /// RFC 7748, section 6.1 (Alice). `wg pubkey` on the Toronto node gives the same
    /// public key for this private key (checked 2026-11-10).
    const RFC_PRIVATE: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    const RFC_PRIVATE_BASE64: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
    const RFC_PUBLIC_BASE64: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";

    #[test]
    fn a_key_pair_is_what_wireguard_itself_derives() {
        let pair = KeyPair::from_private(RFC_PRIVATE);

        assert_eq!(pair.private_key(), RFC_PRIVATE_BASE64);
        assert_eq!(pair.public_key, RFC_PUBLIC_BASE64);
        assert!(is_valid_key(&pair.public_key));
    }

    #[test]
    fn generated_keys_differ_every_time_are_clamped_like_wg_genkey_and_stay_out_of_debug() {
        let first = KeyPair::generate().unwrap();
        let second = KeyPair::generate().unwrap();

        assert_ne!(first.public_key, second.public_key);
        assert_ne!(first.private_key(), second.private_key());
        for pair in [&first, &second] {
            assert!(is_valid_key(&pair.public_key));
            assert!(is_valid_key(&pair.private_key()));
            assert_eq!(pair.private[0] & 0b0000_0111, 0);
            assert_eq!(pair.private[31] & 0b1100_0000, 0b0100_0000);
        }
        assert!(!format!("{first:?}").contains(&first.private_key()));
    }
}

# bf-common
**Status:** Implemented — everything the agent shares with the future control program: reading WireGuard, peer lists, request signing.

## Overview
A library with no I/O of its own. The agent uses it now; `bf-control` will use the same types to build lists and sign calls, so the two sides cannot drift apart.

## Key details
- Code: `crates/bf-common/src/{wg,status,peers,sign,trackers,logins}.rs`.
- **logins.rs** (decision 023): `Login { at, user, from, key, key_name }`; `parse_line` reads one `journalctl -o short-unix` line (`Accepted publickey|password for <user> from <ip> port <n> ssh2[: <TYPE> SHA256:<fp>]`; anything else is `None`; `::ffff:` addresses written plainly); `network(ip)` gives the `/24` or `/48`; `names_from_keygen(text)` reads `ssh-keygen -lf` lines into fingerprint → key name; `from_files(logins, keys, written, now)` gives the logins of the last 15 minutes, named, and refuses a file older than 5 minutes. `DIR`, `LOGINS_FILE`, `KEYS_FILE`, `WINDOW_SECS`, `STALE_SECS` are shared by the agent, the website and `deploy/bf-logins.sh`. No I/O here: the callers read the files.
- **wg.rs**: `parse_dump(text) -> Dump` reads `wg show <if> dump` (tab separated; interface line `private-key public-key listen-port fwmark`, then one line per peer `public-key preshared-key endpoint allowed-ips latest-handshake rx tx keepalive`). The private key and preshared keys are dropped on read. `(none)` endpoints and handshake 0 become `None`. An error carries the line number, never the line. An endpoint it cannot read (such as the link-local `[fe80::1%eth0]:51820`, which is read without its zone, or anything odd) becomes unknown instead of failing the dump. `PeerState`'s `Debug` hides the client address.
- **status.rs**: `build_status(now, &dump, online_secs, desired_version, load1) -> Status`. `Status::logins` (`Option<Vec<Login>>`) is written only when it is `Some`, so an older website reads a new agent, and a new website reads an older agent as "no logins". Online means handshake age strictly below the threshold; a handshake in the future counts as age 0. `mask_endpoint` zeroes the last IPv4 octet and keeps the first four IPv6 groups.
- **peers.rs**: `is_valid_key` (44 characters, canonical base64 of 32 bytes), `Cidr::parse` (needs a prefix, no bits below it), `PeerList::check() -> Desired` (sorted by key; refuses bad keys, bad ranges, repeated keys, ranges held twice; errors name the position only), `judge(stored, incoming) -> Newer | Repeat | Stale`, `plan(current, &desired) -> Plan { add, remove, update }` (ranges compared as sets, so notation does not matter). `PeerSpec::trackers` / `DesiredPeer::trackers` (`specs/trackers.md`): missing means `true` and `true` is not written, so a list of filtered peers reads and writes as it did before the field; a same-version list that differs only in it is `Stale`. `Cidr::ipv4_host()` is the address of an IPv4 `/32`.
- **trackers.rs** (decision 015): `names(list, allow)` reads EasyPrivacy strictly (only exact `||name^`; an exact `@@||name^` or an allow-file line frees the name, the names under it and any blocked name above it; names need two labels, a non-numeric last label and at most `MAX_NAME` = 226 characters (so the zone's `*.` owner names fit 255 bytes); a name under a kept one is dropped), `zone(&names)` writes the RPZ zone (`name CNAME .` and `*.name CNAME .`), `names_in_zone`, and `check_floor(found, previous)` (at least `MIN_NAMES` = 1,000 and at least half of `previous`).
- **sign.rs**: `signed_text`, `sign`, `Verifier::verify(now, &Parts, sig_hex)`: nonce shape (16 to 128 visible ASCII), then signature (constant time), then the 60 s window, then the floor (`Verifier::with_floor`: requests signed at or before it are `Refusal::BeforeRestart`), then the replay cache; `highest_accepted()` is the highest time accepted so far, which the agent keeps on disk. `hex` and `unhex` live here too. Test vectors were computed with Python's `hmac`.

## API / interfaces
The Rust types above are the interface. The JSON shapes are in `specs/agent.md`.

## Dependencies
serde, hmac 0.13, sha2 0.11 (dev: serde_json). Used by: bf-agent.

## Known issues / gotchas
- The nonce cache is in memory only and starts empty when the process restarts. The agent covers that with a floor from its stored replay mark (decision 007); a user of `Verifier` that does not set one has the old gap.
- `Cidr` refuses host bits even though `wg` would accept them (see ADR 003).

## Related
- [bf-agent](bf-agent.md)
- [Strict peer lists](../decisions/003-strict-peer-lists.md), [Signed requests](../decisions/002-signed-requests.md)

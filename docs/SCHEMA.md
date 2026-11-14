# Database schema
**Status:** Schema version 5: version 1 in `crates/bf-control/src/store.rs` (`SCHEMA_1`), version 2 (sign-in) in `crates/bf-control/src/signin.rs` (`SCHEMA_2`), version 3 (the node registry) in `crates/bf-control/src/nodes.rs` (`SCHEMA_3`), version 4 (kept sessions) in `crates/bf-control/src/signin.rs` (`SCHEMA_4`), version 5 (a protocol per node) and version 6 (where each server is) in `crates/bf-control/src/nodes.rs` (`SCHEMA_5`, `SCHEMA_6`). The deployed site runs version 3; version 4 is built and tested, not deployed. The agent keeps its own, separate JSON file, `peers.json` (shape in `specs/agent.md`).

The control program's SQLite database. The path is `BC_DB` (default `/var/lib/barely-free/control.db`). Every table is `STRICT`, and foreign keys are switched on for each connection. Times are Unix seconds (UTC). Only `device_limit`, `tracker_filter`, `published_list.id`, `accounts.is_admin`, `accounts.admin_fail_count` and `mail_log.kind` have CHECK constraints; the code never writes a negative time or version, and reads a negative one as 0.

The file is created with mode 0600 (readable by its owner only; SQLite gives the journal the same mode). A file that already exists keeps its mode. An existing SQLite file that has tables but was not made by this program (version 0 with tables, or without all four of ours) is refused and left alone; so is one with a higher `user_version`. A command that makes a new database file says so on stderr, so a mistyped `BC_DB` is noticed.

## Tables

### `accounts`
Somebody who holds devices. Sign-up is closed, so an admin makes these from the command line.

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER, primary key, autoincrement | Never given out twice, even after a delete |
| `label` | TEXT, not null | 1 to 64 characters, no control characters or text-reordering marks, not only spaces, the command line also refuses one starting with `-` (the database itself does not); the stored text is not trimmed |
| `email_fp` | BLOB, unique | The 32-byte keyed fingerprint of the sign-in email (see version 2 below); null until an admin gives the account an address |
| `device_limit` | INTEGER, not null, default 3 | 0 or more. Counted when a device is added |
| `created_at` | INTEGER, not null | |

### `devices`
One WireGuard peer. Only its public key is kept; the private key is shown once when the device is made and is never stored.

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER, primary key, autoincrement | Never given out twice, even after a delete |
| `account_id` | INTEGER, not null | References `accounts(id)`, `ON DELETE CASCADE` |
| `name` | TEXT, not null | Same rule as a label |
| `public_key` | TEXT, not null, unique | Canonical base64 WireGuard key (checked with `bf_common::peers::is_valid_key`) |
| `address` | INTEGER, not null | The device's tunnel address as an IPv4 number, inside `10.77.0.2` to `10.77.255.254`. `10.77.0.1` is the server. Unique among devices that are not removed (see the index below) |
| `tracker_filter` | INTEGER, not null, default 1 | 0 or 1. Whether the server's DNS blocks trackers for this device. The owner flips it on the account page (`Store::set_tracker_filter`); the published list carries `trackers: false` for a 0 (`specs/trackers.md`) |
| `created_at` | INTEGER, not null | |
| `removed_at` | INTEGER | Null while the device is live. Set by `device remove`; the row is kept as history ([decision 005](decisions/005-removed-devices-are-kept.md)) |

Indexes: `devices_by_account (account_id)`, and the unique partial index `devices_address_active (address) WHERE removed_at IS NULL`, so a removed device's address can be given out again.

### `kicks`
Never a flag on the device: a row per kick, kept after it ends, and kept after the device is removed, so the history stays.

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER, primary key, autoincrement | Never given out twice, even after a delete |
| `device_id` | INTEGER, not null | References `devices(id)`, `ON DELETE CASCADE` (only a hard delete of the device or its account does that; `device remove` only sets `removed_at`) |
| `kicked_by` | TEXT, not null | Who did it (`--by`, default `admin`) |
| `reason` | TEXT, not null, default `''` | At most 200 characters, no control characters or text-reordering marks |
| `started_at` | INTEGER, not null | |
| `until` | INTEGER | End time. Null means until lifted |
| `lifted_at` | INTEGER | Set by `lift`; null while the kick has not been lifted |
| `lifted_by` | TEXT | Who lifted it |

Index `kicks_by_device (device_id)`.

A device is **off the list at time T** when it has a kick with `started_at <= T`, `lifted_at` null, and `until` null or greater than `T`.

### `published_list`
One row (`id` is always 1): the last peer list `publish` returned, so the version never goes backwards (the agents refuse a lower version).

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER, primary key | Checked to be 1 |
| `version` | INTEGER, not null | Starts at 1; +1 each time the list differs from the last one returned |
| `content` | TEXT, not null | The list's peers as JSON, sorted by public key |

`publish` reads the devices and kicks inside one write transaction and writes this row only when the list differs from the stored one, so two programs publishing at once cannot store an older list over a newer one, and the poller's repeated calls write nothing while the list is unchanged. `bf-control list raise <n>` (`Store::raise_version_floor`) sets `version` to `n` and blanks `content` when the stored version is below `n`, so the next `publish` returns `n + 1` although the devices have not changed. It is the way out when a node holds a newer list than a restored database; the poller flags such a node and never raises the version by itself.

### Added in version 2 (sign-in)
Deleting an account (decision 017) removes its row; the cascades take its devices, their kicks and its sessions, and the code deletes its pending sign-in codes and blanks its fingerprint in `mail_log`. No email address and no sign-in code is ever stored. See `specs/accounts-and-admin.md` for the rules and `docs/modules/bf-control.md` ("Sign-in store") for the code.

**`accounts`, new columns**

| Column | Type | Notes |
|---|---|---|
| `is_admin` | INTEGER, not null, default 0 | 0 or 1. Set only from the command line (admin slice) |
| `admin_pw_hash` | TEXT | Argon2id hash of the admin password, or null (admin slice) |
| `admin_fail_count` | INTEGER, not null, default 0 | wrong admin passwords in a row (admin slice) |
| `admin_locked_until` | INTEGER | the admin password is refused until this time (admin slice) |

`accounts.email_fp` (from version 1) now has a use: the 32-byte keyed fingerprint `HMAC-SHA256(fp key, lowercase(trim(email)))`. It is unique; `Store::set_email_fp` refuses a fingerprint another account has.

### `login_codes`
One row per code asked for. At most one row per address: a new request deletes the old one.

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER, primary key, autoincrement | used in the mail's idempotency key (`signin/<id>`) |
| `email_fp` | BLOB, not null | who it was made for |
| `code_mac` | BLOB, not null | `HMAC-SHA256(code key, email_fp || code)`; never the code |
| `created_at` | INTEGER, not null | |
| `expires_at` | INTEGER, not null | `created_at` + 600; the code is dead at exactly this second |
| `tries` | INTEGER, not null, default 0 | wrong tries; the fifth ends the code |
| `used_at` | INTEGER | set when a right code is used; a used code never works again |

Index `login_codes_by_email (email_fp)`. Rows older than a day are deleted.

### `sessions`
| Column | Type | Notes |
|---|---|---|
| `id` | TEXT, primary key | 32 lowercase hex characters (128 bits), the lookup id |
| `secret_hash` | BLOB, not null | `SHA-256` of the 64-hex-character secret (256 bits); the secret is only in the person's cookie |
| `account_id` | INTEGER, not null | References `accounts(id)`, `ON DELETE CASCADE` |
| `csrf` | TEXT, not null | 32 hex characters, the token for the hidden field of every form |
| `created_at` | INTEGER, not null | |
| `expires_at` | INTEGER, not null | `created_at` + 60 days; the session is dead at exactly this second. For a kept session (`keep = 1`) a signed-in page moves it to 60 days from then, at most once a day, never past `created_at` + 365 days |
| `admin_until` | INTEGER | until when the admin password has been accepted: 30 minutes after a correct password; cleared by the Lock button, by taking admin away and by setting a new admin password for the account (admin slice; no schema change) |
| `keep` | INTEGER, not null, default 0 | 0 or 1 (CHECK). 1 when the person ticked "Keep me signed in on this device" on `/verify`; only those sessions are renewed (version 4) |

Index `sessions_by_account (account_id)`. Every sign-in makes a new id. An account keeps its newest ten sessions. Expired rows are deleted whenever a code is requested or a session is made.

### `mail_log`
What the three limits and the daily budget count. Rows older than a day are deleted.

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER, primary key, autoincrement | |
| `sent_at` | INTEGER, not null | the time of the event (for a `request`, when it was asked) |
| `email_fp` | BLOB | the address's fingerprint |
| `ip_fp` | BLOB | `HMAC-SHA256(fp key, "ip" NUL address)`, or null when there is no address |
| `kind` | TEXT, not null | `request` (a code was asked for, known address or not), `sent` (Resend took an email), `failed` (it did not), `quota` (Resend said its quota is used up) |
| `outcome` | TEXT, not null, default `''` | a note. `new` on a `request` row made while sign-up is open for an address with no account; the daily cap on new addresses counts these rows since 00:00 UTC |

Index `mail_log_by_time (sent_at)`. The rules, in this order, each answered the same for known and unknown addresses: paused if a `quota` row or 90 `sent` rows exist since 00:00 UTC; limited if the address has 3 `request` rows in the last hour (`sent_at` newer than now minus 3600) or the network address has 10; otherwise the request is logged, and only then is an account looked for.

### `nodes` (added in version 3)
The registry of VPN nodes the poller visits. A node's signing secret and pinned root certificate are not here: they are files in the nodes directory (`BC_NODES_DIR`, `<name>.secret` and `<name>.pem`), so a backup of the database never carries a node's key. See `specs/poller.md` and `docs/modules/bf-control.md`.

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER, primary key, autoincrement | ids are never reused |
| `name` | TEXT, not null, unique | 1 to 32 characters of `a-z`, `0-9` and `-`, starting with a letter, not ending with `-`; the node's name in its certificate (`<name>.agent.internal`) and the stem of its two files |
| `title` | TEXT, not null | what the site calls it ("Toronto"); 1 to 40 characters, no control or text-reordering characters |
| `place` | TEXT, not null | where it is ("Canada"); same rules as `title` |
| `address` | TEXT, not null | the agent's IP address and port, in the canonical spelling `SocketAddr` writes (`192.0.2.7:8443`). Since version 5 two agents of one server share it; `UNIQUE (address, protocol)` |
| `protocol` | TEXT | `wireguard` or `amneziawg` (CHECK): what the agent's interface speaks, so which list it gets and which devices it serves. Null for a node registered before version 5 until `node set-protocol` (version 5) |
| `enabled` | INTEGER, not null, default 1 | 0 or 1 (checked); the poller visits only enabled nodes |
| `created_at` | INTEGER, not null | |
| `lat` | REAL | the server's latitude in degrees, -90 to 90 (CHECK), for "Closest to you" (decision 014); set by `node set-location`. Null until set (version 6) |
| `lon` | REAL | its longitude, -180 to 180 (CHECK); set or null together with `lat` (CHECK) |

The table is `STRICT`. Removing a node deletes its row and leaves its files.

## Relationships
- An account has 0 to `device_limit` devices; a device belongs to exactly one account. Deleting an account would delete its devices (no command does that yet).
- A device has any number of kicks.
- An account has up to ten sessions (they go with the account) and at most one fingerprint; `login_codes` and `mail_log` rows point at no account, only at a fingerprint, so a code can be made and checked for an address with no account without anything showing it.
- **Ids are never reused.** `accounts`, `devices` and `kicks` use `AUTOINCREMENT` (SQLite keeps the highest id in `sqlite_sequence`), so after a delete a new row gets a new id and a stale `kick 3` cannot reach a different device. Addresses, in contrast, are reused on purpose.
- Removing a device keeps its row and its kicks (`removed_at` is set). A removed device is off the list, not counted against the limit, cannot be kicked, and its public key can never be added again. Its address is free at once.
- Addresses are unique among devices that are not removed. The next device gets the lowest free address from `10.77.0.2`, so a freed address is used again before any higher one.
- `published_list` is derived data (see [decision 004](decisions/004-list-from-database-and-time.md)); it can be dropped without losing a fact, except the version number.

## Migrations
- **Version 1** (2026-11-10, `AUTOINCREMENT` ids added the same day with Lao's yes, before anything was deployed, so the version did not change): the four tables above, `PRAGMA user_version = 1`. Applied inside one transaction when a database is opened and its version is 0.
- **Version 1 again, `removed_at` added in place** (2026-11-10, decision 005, still before anything was deployed): `devices.removed_at` and the partial unique index on `address` replace the inline `UNIQUE`. A database file made earlier the same day has no such column; opening it gives a clear error telling you to delete the file.
- A database whose `user_version` is higher than the program's is refused with a clear message, so an old binary never writes to a newer schema.
- **Version 2** (2026-11-10, a real migration, `upgrade_to_2`): adds the four `accounts` columns and the tables `login_codes`, `sessions` and `mail_log`, then sets `PRAGMA user_version = 2`. It runs inside one Immediate transaction that looks at the version again first, so two programs opening the same version-1 database build the new tables once. A version-1 database keeps every row (accounts, fingerprints, devices, kicks, and the list version a node has seen). A database with a higher version than the program's is refused.
- **Version 3** (2026-11-10, `upgrade_to_3`): adds the `nodes` table, then sets `PRAGMA user_version = 3`. Like version 2 it runs inside one Immediate transaction that looks at the version again first. Every existing row is kept.
- **Version 4** (2026-11-10, `upgrade_to_4`): `ALTER TABLE sessions ADD COLUMN keep INTEGER NOT NULL DEFAULT 0 CHECK (keep IN (0, 1))`, then `PRAGMA user_version = 4`, in one Immediate transaction that looks at the version again first. Every existing session gets 0 and keeps its expiry, so it behaves exactly as before. After this, a version-3 binary refuses the database: a rollback needs the database backup too.
- **Version 5** (2026-11-10, `upgrade_to_5`): the `nodes` table is rebuilt (SQLite cannot drop a UNIQUE): `protocol` is added (null for every existing node) and `address` is unique only together with `protocol`. Every row and id is copied and the table's `AUTOINCREMENT` counter is carried over, so no node id is given out twice. One Immediate transaction that looks at the version again first. A version-4 binary refuses the result.
- **Version 6** (2026-11-11, `upgrade_to_6`): `ALTER TABLE nodes ADD COLUMN lat REAL ...` and `lon REAL ...` with their CHECKs, then `PRAGMA user_version = 6`, in one Immediate transaction that looks at the version again first. Every node starts with no location; the published list does not change. A version-5 binary refuses the result.
- Planned: a second address per device for the Restricted-network profile (step 6).

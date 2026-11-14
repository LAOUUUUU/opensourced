# 005: A removed device is kept as history
**Status:** Accepted — 2026-11-10 (Lao approved the plan and the three choices below)

## Context
`device remove` used to run `DELETE FROM devices`, and `kicks.device_id` is `ON DELETE CASCADE`, so removing a device also deleted every kick it had. An admin who kicked a device for abuse and then tidied up with `device remove` lost who kicked it, why and when. [Decision 004](004-list-from-database-and-time.md) and `docs/SCHEMA.md` promise that kicks stay as history. A code review found the contradiction (finding 8, 2026-11-10).

## Decision
- Removing a device sets `devices.removed_at` (Unix seconds) and nothing else. The row, its public key, its address and its kicks stay.
- A removed device is **not** on the peer list, **not** counted against the account's device limit, **not** in `device list` or `account list`'s count, and cannot be kicked (that answers "no device with that id"). Removing it twice is refused the same way. (Its kicks could not be lifted either until [decision 012](012-a-kick-blocks-adding-devices.md): a kick still in force on a removed device now holds its account, so it can be lifted.)
- Its **address** is free at once: the uniqueness of addresses is a partial unique index (`devices_address_active … WHERE removed_at IS NULL`), and the "lowest free address" query ignores removed rows. Kicks point at the device id, so an old kick is never confused with the next device that gets the address. (An address rest period was considered and not chosen: it adds logic for a confusion the id already prevents.)
- Its **public key** stays unique across removed rows, so a removed key cannot be added again. Otherwise "kick, remove, add the same key" would shed the kick.
- `bf-control kick list [<device-id>]` shows the kept history, including kicks of removed devices.
- The schema is changed **in place** (still version 1, as the `AUTOINCREMENT` change was earlier the same day), because nothing is deployed and `address` had an inline `UNIQUE` that only a table rebuild could turn into a partial index.

## Consequences
- The `devices` and `kicks` tables only grow. At this scale (a closed beta, at most 65,533 addresses) that does not matter.
- Every query about live devices must say `removed_at IS NULL`: `devices()`, `peers_at`, the limit count, the address search, `require_device`, the account counts. Tests cover each (and a mutation check that drops the filter from `peers_at` and the address search fails four of them).
- A database file made with the earlier draft of schema 1 has no `removed_at`; opening it gives a clear "delete the file" error (`StoreError::StaleDraft`). There is no production database yet.
- `kick` looks for the device inside its write lock, so a kick cannot land on a device another program is removing at that moment.
- `accounts` still `ON DELETE CASCADE`s devices and kicks, but no command deletes an account.
- `remove_device` is one `UPDATE … RETURNING`, so it is atomic and a second removal cannot succeed.

## Related
- [SCHEMA](../SCHEMA.md), [bf-control](../modules/bf-control.md), [decision 004](004-list-from-database-and-time.md), `specs/control-core.md`
- Amended by [decision 012](012-a-kick-blocks-adding-devices.md): unique keys stopped a kick being shed only while the admin made every key. Now a kick in force, even on a removed device, stops its account adding a device, and a removed device's kicks can be lifted.

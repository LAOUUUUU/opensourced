# 012: A kicked account cannot add a device until the kick ends
**Status:** Accepted, built, not deployed — 2026-11-10 (found by the security review of `dev`; Lao: "Yes, fix it")

## Context
A kick is a row on one device ([decision 004](004-list-from-database-and-time.md)), and `peers_at` leaves out only that device. [Decision 005](005-removed-devices-are-kept.md) kept public keys unique so that "kick, remove, add the same key" could not shed a kick. That was enough while only the admin could add devices.

The account page now lets the owner add a device, and the server makes a **new** key every time, so uniqueness never comes into it. A security review of `dev` (2026-11-10) found the gap. A kicked owner could press "Add a device", or remove the kicked device first if at the limit, and get a fresh file with a new key. The poller sent it to the node within seconds, and a removed device's kick also dropped out of the admin's "In force now". The add-a-device page was already deployed.

## Decision
- **While any device of an account has a kick in force, removed devices included, the account cannot add a device.**
  - `Store::add_device_with` checks this inside its write lock, so a kick made at the same moment is not missed. It answers `StoreError::Kicked`.
  - The check comes before the device limit, so a kicked account at its limit is told about the kick, not the limit. It also comes before the private key is shown, so nothing is printed.
  - It applies on every path. The account page answers 403 "A device is switched off", and `bf-control device add` is refused (exit 1).
- **The owner cannot remove a device that has a kick in force.** `Store::remove_own_device(account, device, now)` checks ownership and the kick in one write lock. The account page uses it and answers 403 "This device is switched off". Another account's device, or a missing one, is still a 404.
- **Removing a kicked device does not end its kick.** The admin can still remove it (`device remove`, `/admin/devices/remove`).
  - The kick stays in force: it still blocks adding a device, it counts in the overview, and it stays in "In force now", marked "(removed)", with a Lift button.
  - `lift`, on the command line and on the page, now works on a removed device's kicks. `kick` still refuses a removed device. This amends decision 005, which said a removed device "cannot be kicked or lifted".
  - Cleaning up after a kick (decision 005) therefore keeps the person out.
- **A kick that runs out or is lifted frees the account at once.** A kick that has not started yet does not count, the same rule `peers_at` uses.

## What a kick still does not do
- **It does not cut off the account's other devices.** `peers_at` leaves out only the kicked device, so their files keep working, and could even be copied onto the kicked phone. To cut a person off, kick each of their devices (the Devices page lists them with their owner).
- **It does not stop another account.** With open sign-up on ([decision 010](010-open-sign-up.md), off today), a kicked person could make a new account with another address.

An account-level suspension that `peers_at` reads, or a "kick every device of this account" action, is a later step.

## Consequences
- The kicked device stays on the owner's account page. The page does not say it is kicked, and both forms give the "switched off" answer.
- **After deploying, look for the gap having been used.** Earlier removals do not record who did them. A kick on a device the owner removed before this fix counts again at once. But a device added to a kicked account in the meantime is live and not kicked. Run `bf-control kick list` and `bf-control device list` on the VM and compare the times.
- Tests:
  - Five new store tests (`store.rs`): an add is refused until the kick ends; the kick is named at the limit and a lift frees the account; a kick that has not started does not count; an admin removal does not free the account, and a lift does; owner removal.
  - One new page test (`app.rs`) and one new command test (`cli.rs`, no key printed).
  - Four tests changed on purpose because the rule changed: two in `store.rs` (lifting a removed device's kick), the overview count in `adminauth.rs`, and the Kicks page in `app/tests/admin_pages.rs` (a removed device's kick in force, then lifted from the page).

## Related
- [decision 004](004-list-from-database-and-time.md), [decision 005](005-removed-devices-are-kept.md), [bf-control](../modules/bf-control.md)

# 017: Deleting an account removes it and everything it owns
**Date:** 2026-11-12
**Status:** Accepted. Lao said "yeah sure add it" to the admin account page, admin delete and "Delete my account".

## Context
Sign-up opened on 2026-11-12. Before this, there was no way to delete an account: no button and no admin command. The coming privacy page needs one, and Lao, as admin, could make accounts but could not open or delete one.

## Decision
- **`Store::delete_account` (one Immediate transaction).** It removes the account row. The database's own cascades remove its devices (live and removed), their kicks and its sessions. The sign-in codes waiting for its address are deleted. Its fingerprint is blanked in `mail_log`, whose lines stay so the day's mail caps keep counting. No schema change.
- **The servers.** The next published list has none of its devices. The handlers ask the poller for a pass at once, so they leave the servers within seconds. Their addresses are free again.
- **Admin.**
  - `/admin/account?id=N`, linked from each label on Accounts, shows the account, its devices with their last connection, and its kicks.
  - `POST /admin/accounts/delete` deletes it when its label is typed exactly. It needs the admin password given in the last half hour. An admin cannot delete their own account. The log records which admin deleted which account, by id.
- **Self.** On the account page, `POST /account/delete` deletes your own account when you type "delete". It ends the session with it and clears the cookie. An admin account cannot do this; it shows a note instead.

## Rejected
- **A soft delete (`deleted_at`).** It would keep the address fingerprint, which a deletion should not.
- **Refusing to delete while a kick is in force.** It would trap a person who wants their data gone. Making a new account was always possible anyway.

## Consequences
- **Deleting cannot be undone.** The nightly encrypted backups still hold the account for up to 30 days (decision 016). The pages say so.
- **A deleted address can sign up again** as a new account.
- **The kick history of a deleted account goes with it.** The log line of the deletion stays.

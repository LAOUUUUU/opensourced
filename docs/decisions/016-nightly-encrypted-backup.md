# 016: A nightly backup, encrypted to Lao's age key, kept on both nodes
**Date:** 2026-11-11
**Status:** Accepted. Lao asked for the backup ("can u do these") and chose "Both servers". Brief: `research/backup/RESEARCH.md`. Spec: `specs/backup.md`.

## Context
The web VM is a VM on a home PC. It holds the only copy of two things:
- the accounts database;
- the fingerprint key, `control.key`. Without it, no stored email fingerprint matches an address again.

If that disk dies, every account is gone. The nodes would also refuse the list of a fresh database (decision 004).

## Decision

**The copy: `bf-control backup <file>`.**
- Takes the copy with `VACUUM INTO`, which gives one consistent snapshot while the website runs and leaves no deleted content in the copy.
- Opens the database read-only, so it never makes, upgrades or changes it.
- Writes the copy 0600 into a folder only its owner can open, checks it with `integrity_check`, and removes it on any failure.
- No new crate.

**The nightly run: `deploy/bf-backup.sh`.**
- Runs from `bf-backup.service`, started by `bf-backup.timer` at 08:30 UTC (03:30 in Toronto in winter), within half an hour. `Persistent=true` catches up a night the VM was off.
- Runs as `barely-free`, inside the website's sandbox, with write access only to `/var/lib/barely-free`.
- Packs the copy, `control.key` and a manifest of SHA-256 sums into a tar.
- Encrypts it with `age -R /etc/barely-free/backup.recipients`, which holds Lao's public key. The VM can lock a backup but never open one.
- The plain files exist only in the service's tmpfs runtime folder and are removed on exit.

**Where it goes: both nodes, over SSH.**
- The VM's key, made on the VM, is the only key of a `bf-backup` user on each node, as `restrict,command="/usr/local/bin/bf-backup-receive"`.
- The receiver accepts only `put control-YYYYMMDDTHHMMSSZ.tar.age`, at most 64 MiB, and never writes over a file (it links into place). It keeps the newest 30.
- The VM pins each node's host key (`StrictHostKeyChecking=yes`) and sends to every node. One node failing does not stop the other.
- `authorized_keys`, `.ssh` and the receiver belong to root, so `bf-backup` cannot loosen its own key.

**Watching it.**
- The script writes `/var/lib/barely-free/backup-status`.
- The admin overview shows it as a "Backups" line: a quiet line for a good night, and a warning for no backup yet, a failure, a missed server, a run older than 36 hours, or a file that cannot be read.

**Restoring: `deploy/restore-backup.sh`, on the Mac with Lao's age key.**
- `fetch` decrypts the newest backup, refuses an archive holding anything else, and checks every sum and `integrity_check`. It changes nothing anywhere, and doubles as the drill.
- `put` stops `bf-control`, keeps the old database, key and journal aside, restores, starts, and runs `node check` for every node.
- A node AHEAD of the restored list is shown with the `bf-control list raise <n>` to run. That command already existed.

## Rejected
- **Cloudflare R2.** It needs a payment method on file and a secret token typed onto the VM. Its tokens have no write-only level, so bucket lock rules would be needed to stop a thief deleting backups. It would also put a third party in the path.
- **Backblaze B2.** It needs a new account and a secret key on the VM. It remains the way to add a third copy off our own servers.
- **Litestream.** v0.5 dropped age encryption, with no date for its return, and it is a new program on the VM.
- **A passphrase (`age -p`).** It would have to live on the VM to run unattended, which defeats the encryption.
- **The admin's computer pulling the backups.** It is not always on, and it is not a server.

## Consequences
- **Losing Lao's age secret key makes every backup useless.** Keep it in a password manager and on paper, never on the VM, and not left on the Mac.
- **Both copies are with one hosting company.** If that account is lost while the VM is also lost, the backups go too.
- **A node's root can delete that node's copies but cannot read them.**
- **A restore loses everything since the backup**, at most about a day. Devices made since then vanish from the list. Sessions in the copy become valid again.
- **Backups hold the fingerprint key.** Anyone with a backup and Lao's age key could test email addresses against the fingerprints.
- **The front page says it under "What we keep":** an encrypted copy goes to our two servers every night, and each is deleted after 30 days.
- **The nodes' fail2ban** bans an address after 4 failed logins. A broken VM key would get the VM banned for an hour at a time. The status line would show the failures.

## Amended 2026-11-12
The copy leaves out the sign-in records (`mail_log`, `login_codes`). The privacy policy says they are gone after a day; the copies last 30 nights and sit next to the fingerprint key, which can reverse an IPv4 fingerprint. They are emptied in the copy, which is then vacuumed again with temporary data in memory. A restored database starts with empty sign-in records: pending codes stop working and the day's mail limits start again from zero. The copies `deploy-web.sh` keeps before each update are made the same way: by the new program's `backup`, as the website's user, instead of `cp -p`. If that fails, the old program starts again and nothing is installed. A test holds the script to it.

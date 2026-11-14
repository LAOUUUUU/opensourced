# 023: An email when someone logs in to a server from somewhere new
**Date:** 2026-11-12
**Status:** Accepted. Lao: "Yes, approve both" (the brief `research/login-alerts/RESEARCH.md` and the spec `specs/login-alerts.md`). Built, not deployed.

## Context
Infostealer malware targets SSH keys, and a stolen key opens all three servers. A thief with a key logs in exactly as the admin does, and nothing told anyone. The server-down alerts (`research/alerts/RESEARCH.md`) already email Lao through Resend from the website.

## Decision
- **What counts as new: a (key, network) pair.** The key is its `SHA256:` fingerprint, or `password`. The network is the address's `/24` (IPv4) or `/48` (IPv6). The user and the server are shown but are not part of the pair, so Lao's usual key from home is quiet on every server, and the same key from a new network emails once.
- **Where the logins come from.**
  - Every server runs a root timer, `bf-logins.timer`, once a minute. It writes the last 15 minutes of `Accepted` lines from `journalctl -u ssh` and `ssh-keygen -lf` of the `authorized_keys` files into `/var/lib/barely-free-logins` (root, group `bf-logins`, 0750 and 0640). It has no network, may write only that folder, and keeps only `CAP_DAC_READ_SEARCH`, to read other users' `.ssh`.
  - The agents (dynamic users with no home, which can read neither the journal nor `/root/.ssh`) are put in `bf-logins` by a drop-in. They read the two files and add the logins to their signed status (`logins`). The website is in the group on the VM and reads the VM's own. No new secret is put on any server.
  - The approved brief had the agents run `journalctl` themselves. That turned out impossible in their sandbox: an early check ran it as root and missed this. Giving them the `systemd-journal` group would let them read every log on the server and still not the key names. The spec records the change.
- **What is remembered:** `/var/lib/barely-free/known-logins`, one `<key>\t<network>` per line, 0600, written whole and atomically. Saving merges with the file, so the seeding command and the website never lose each other's pairs.
- **Learning, not alerting:** with no file, the first look learns what it sees. `deploy/seed-known-logins.sh` feeds 90 days of all three journals to `bf-control logins learn` on the VM (nothing stored on the Mac), then restarts the website.
- **The email** shares the down alerts' look (30 s), their one-email-per-look rule and their 10-a-day cap; past the cap the full news is logged. The subject names the server ("New login to Dallas"), and the login lines come before any down news, because a stranger on a server matters more. Each line has the server, user, UTC minute, full address, key name (or "a key not in authorized_keys", or "a password") and fingerprint, then "If this wasn't you, the key may be stolen: remove it from authorized_keys on every server."
- **What the website trusts from a node:** user names of letters, digits, `.`, `_`, `-` (32 at most), fingerprints of the right shape, key names stripped of control and direction characters and cut to 80. Any login that fails is dropped alone. The VM's own lines pass the same check.

## Alternatives rejected
- **Mail from each server** (`pam_exec` or `sshrc`): every server would need a mail key, and a thief who is root removes the hook first.
- **Every login emails:** Lao logs in many times a day; the cap would be gone by noon and the one that matters lost in the noise.
- **Letting the website or the agents read the journal** (`systemd-journal` group): they would read every log on the server, not just sshd's, and still could not name the keys.
- **Pairs per server:** a key that is normal from a network on one server is normal on the others; per server would only add noise.

## Consequences
- A thief on the same `/24` as Lao, or one who logs in from a network Lao used in the last 90 days, is not caught. A thief who stops the agent within seconds of logging in is not caught by this either, but the server then stops answering and the down alert fires after 3 minutes.
- Lao's own logins from a new VPN exit or a new home address send one email each (that is the point); a busy day can use up the 10.
- An agent older than this one reports no `logins`: the website logs it once per agent and treats it as reporting nothing. Deploy order: the website, then the seed script, then the agents.

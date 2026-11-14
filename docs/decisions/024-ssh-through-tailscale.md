# 024: SSH to the servers only through Tailscale
**Date:** 2026-11-12
**Status:** Accepted and done (Lao: "Yes, approve both", then "do the tailscale" the same day). On 2026-11-12, all three servers joined, were tagged and put under this policy; key expiry was turned off; the backups moved to Tailscale; and public SSH was closed.

## Where it stands (2026-11-12)
- **Joined** by Lao with the join script (Tailscale 1.104.7): `dallas` <dallas tailscale ip>, `toronto` <toronto tailscale ip>, `web` (the VM) <web tailscale ip>, in the tailnet `<your-tailnet>.ts.net`. Tailscale SSH off, the servers' DNS untouched, the VPN agents, website and tunnel unaffected.
- **Tagged afterwards:** the first keys were not tagged, so the servers joined as Lao's own devices. The first policy save had not taken either: the tailnet still had the default allow-all and an unused `tag:Servers` owned by `autogroup:it-admin`. After Lao pasted this policy, the servers were tagged in the console (`tag:node`, `tag:web`).
- **Checked from the servers' own packet filters** (`tailscale debug netmap`, not the console): the VM accepts only the admin's Mac on 22; the VM reaches both nodes' 22 but not their 8443; Dallas reaches nothing (not the VM, Toronto or the Mac).
- **SSH over Tailscale** from the Mac to `dallas`, `toronto` and `web` by name works. Each host key matched the one known for the server's public address (`-o HostKeyAlias`). The three logins (from a new network) sent one login-alert email, as decision 023 intends.
- **Backups over Tailscale (2026-11-12, Lao: "u can do those"):** the VM's `/etc/barely-free/backup-targets` now names `bf-backup@<toronto tailscale ip>` (Toronto) and `bf-backup@<dallas tailscale ip>` (Dallas). Its `known_hosts` has lines for those addresses with the same host keys already pinned for the public ones, which stay too, so going back is a one-line edit. `.before-tailscale` copies of both files are kept. The nodes' backup key has no `from=` limit, so nothing changed on them. One backup run by hand went to both over Tailscale: `control-20261113T034420Z.tar.age`, 102,616 bytes, 3 kept on each node. If `deploy/setup-backup.sh --finish` is ever run again, give it `known_hosts` lines with the Tailscale addresses, or it writes the public ones back.
- **Key expiry off (2026-11-12):** retagging had not turned it off, so it was disabled in the console for `dallas`, `toronto` and `web`. The admin disabled key expiry in the console for the three. The Mac's `tailscale status --json` now shows no `KeyExpiry` for any of them.
- **The hosting console** works for Dallas and Toronto, Lao says (2026-11-12): there are three ways back in, including restarting in safe mode and entering emergency mode through the panel.
- **Public SSH closed (2026-11-12, Lao: "u can do those")**, one server at a time, each tested before the next:
  - on all three, `/etc/ssh/sshd_config.d/zz-tailnet-only.conf`: `Match Address *,!100.64.0.0/10,!fd7a:115c:a1e0::/48` with `DenyUsers *`. It was installed only after `sshd -T` gave the same effective config for a tailnet address, and the same plus `denyusers *` for a public one; then `systemctl reload ssh`;
  - on Dallas and Toronto, `ufw delete limit 22/tcp` (IPv4 and IPv6);
  - the VM has no ufw (haproxy 443, the honeypot on 2223 and cloudflared must keep working), so its sshd layer is what closes it;
  - checked: SSH over Tailscale from the Mac works to all three; from the VM, the nodes' public 22 gets no answer while their Tailscale 22 (backups) and public 8443 (the poller) answer; a public login to the VM's 2222 is refused ("not allowed because listed in DenyUsers"); the website and the honeypot keep working.
- **The Mac** trusts the servers' Tailscale names: `~/.ssh/known_hosts` has lines for them with the same host keys as the public addresses (`known_hosts.before-tailscale` kept). The README, `CLAUDE.md` and `seed-known-logins.sh` use the names.
- **To undo on a server** (from the console if need be): delete `zz-tailnet-only.conf` and `systemctl reload ssh`; on a node also `ufw limit 22/tcp`.

## Context
Infostealer malware targets SSH keys, and a stolen key that opens all three servers works from anywhere on the internet. Brief: `research/tailscale-ssh/RESEARCH.md`. The login alerts (decision 023) report a stolen key's use; this stops it working from outside the tailnet at all.

## Decision
- **Normal OpenSSH, reached only over Tailscale, keys still required.** Not Tailscale SSH: with it, a taken-over Tailscale account would be root on every server. Here a login needs the Tailscale account *and* an SSH key.
- **Two tags, not the brief's one `tag:server`:** `tag:node` (Dallas, Toronto) and `tag:web` (the VM). Grants only allow, so one tag could not let the VM reach the nodes for the backups without also letting the nodes reach the VM and each other.
- **The policy** (`deploy/tailscale-policy.hujson`, pasted by Lao into the admin console; grants, which deny everything they do not allow): Lao's own devices keep full access to each other, as under the default policy; Lao's devices reach the servers on `tcp:22` only; the VM reaches the nodes on `tcp:22` (the backups); nothing else between servers. There is no `ssh` section, so Tailscale SSH is off in the whole tailnet. A test parses it and checks those rules.
- **Joining:** `deploy/tailscale-join.sh <name> <host>` (run by Lao, who types the key):
  - the key is read with a hidden prompt, refused unless it is `tskey-auth-` and letters, digits and `-`, and sent as the first line of the one SSH connection's standard input, never as an argument;
  - on the server it goes into a 0600 file in `/run`, is used as `tailscale up --auth-key=file:<it>`, and is removed when the script ends, whatever happens;
  - the key is one-off and pre-tagged, so the script names no tag; tagged devices do not expire;
  - `--hostname=<name>`, `--accept-dns=false` (the servers' own DNS is left alone), no `--ssh`.
- **Installing:** from Tailscale's stable apt repository for Debian 13 (trixie, all three servers). The repository's signing key is checked into this repo (`deploy/tailscale-archive-keyring.gpg`, fingerprint `2596 A99E AAB3 3821 893C 0A79 458C A832 957F 5868`, the same bytes fetched from the Mac and from Dallas on 2026-11-12) and sent with the script, rather than downloaded on each server. A key rotation then shows as a failed `apt-get update` and a diff here, not a silent new trust.
- **Order** (each step tested before the next; nothing is closed before SSH over Tailscale works and the hosting console has been tried):
  1. Lao: two-step login on the Tailscale account and old sessions signed out; the policy pasted; one one-off tagged key per server; the hosting console tried for Dallas and Toronto.
  2. Lao runs the join script for each server.
  3. SSH from the Mac to each server by its Tailscale name works.
  4. The backup targets move to the nodes' Tailscale addresses (host keys re-pinned) and one backup runs by hand.
  5. Public SSH closes: on the nodes `ufw allow in on tailscale0 to any port 22`, then the public 22 rule goes; on the VM ufw is enabled with 22 allowed only on `tailscale0` and 2223 (the honeypot) open.
  6. README and memory switch every deploy command to the Tailscale names.

## Alternatives rejected
- **Tailscale SSH:** one account would be enough to be root everywhere.
- **Tailscale's `install.sh` piped to `sh`:** it adds the same repository, but trusts whatever the download says at that moment; the checked-in key is reviewed once.
- **A key on the command line** (`tailscale up --auth-key=tskey-…`): it shows in the process list and can land in a shell history.
- **One tag for all servers:** see above.

## Found while doing it
- **Tailscale's firewall rules come before ufw.** `ts-input` is the first jump in INPUT and accepts everything arriving on `tailscale0`, so ufw never sees tailnet traffic and the Tailscale policy is the only filter for it. The brief's step "allow 22 on `tailscale0` in ufw" therefore does nothing; the policy above, checked in the packet filters, is what limits tailnet traffic to SSH.
- **VPN users and the tailnet:** `ts-forward` is the first jump in FORWARD, and it accepts everything going out on `tailscale0`. Traffic from a VPN user to a 100.x address (or to Tailscale's DNS at 100.100.100.100) would be forwarded into the tailnet with the user's own source address. Peers drop it, because that address is not the server's. As defence in depth (Lao: "Yes, add it", 2026-11-12), `deploy/node-tailnet-guard.sh` drops traffic from `wg0` and `awg0` to `100.64.0.0/10` and `fd7a:115c:a1e0::/48` in the raw table, which Tailscale does not touch. The rules go live first; then the same lines go into each interface's file as `PostUp`/`PostDown`, checked with `wg-quick strip`/`awg-quick strip`, with a `.before-tailnet-guard` copy kept. Done on Dallas and Toronto on 2026-11-12. An AmneziaWG user on Toronto stayed connected through it; the drop counters read 0.
- **The signing key** is now kept up to date by Tailscale's own `tailscale-archive-keyring` package, which apt installed with Tailscale and which owns `/usr/share/keyrings/tailscale-archive-keyring.gpg`. The copy in this repo only serves the first install.
- **Connections over Tailscale skip ufw's 6-per-30-seconds limit on SSH,** since ufw never sees them.

## Consequences
- The Tailscale account becomes the front door; its login needs two-step login.
- The backups depend on Tailscale on the VM; a night without it shows as a failed backup in the admin overview.
- If Tailscale fails on a server after step 5, only the hosting console (nodes) or the host PC (VM) gets back in.
- A pasted key in a chat transcript counts as exposed: revoke it and make a new one (2026-11-12, a key was pasted into the session and not used).
- Not yet checked live: how Tailscale's netfilter rules sit beside the VPN servers' WireGuard forwarding and isolation rules. After the join, check that a VPN device cannot reach any tailnet address and that VPN traffic is unchanged.

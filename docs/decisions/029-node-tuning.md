# 029: The servers' tuning lives in the repository; UTC clocks, UDP GRO forwarding, serve-expired
**Date:** 2026-11-15
**Status:** Accepted and applied on Dallas and Toronto on 2026-11-15 (Lao: "Go"; for Toronto's kernel warning, "Keep 117, finish"). It came out of Lao's question of 2026-11-15 ("anything we can do to the servers to maximize performance or feature?"). A read-only check that day found Dallas and Toronto healthy and nearly idle, with the main network tuning already in place, and a short list of small, reversible changes (`research/server-tuning/PROMPT.md`).

## Context
- `/etc/sysctl.d/99-vpn.conf` (forwarding, BBR with `fq`, 7.5 MB socket buffers, a 5,000-packet input queue, TCP MTU probing) was written by hand on both servers (the same 210 bytes on each) and was in no repository file, so a new server would not get it.
- Tailscale recommends UDP GRO forwarding on Linux machines that forward traffic (https://tailscale.com/kb/1320/performance-best-practices). A VPN server forwards every user's traffic, and `ethtool` was not installed.
- ufw logged about 4,300 `[UFW BLOCK]` lines a day on each server, all internet scans, into the kernel log. fail2ban reads sshd's log, not ufw's.
- The clocks ran in `Asia/Kolkata`, so logs, `last` and every `OnCalendar` timer were in Indian time while everything else in the project is UTC.
- unbound refreshes popular names before they expire (`prefetch`), but an expired name still waited on a full fetch from Quad9, and a slow or failing upstream meant no answer at all.

## Decision
- **`deploy/node-tune.sh`** does the node side; `deploy/node-sysctl.conf` is the sysctl file, byte for byte what the servers had (no value changed: the measurements gave no reason, see below), plus one later change with a reason: the connection-tracking table (next point). The script is idempotent, needs ufw active and root, changes the running system first (`sysctl -p`, `ethtool -K`) so a failing command leaves no file written, then writes the files, turns ufw's logging off and sets the clock to UTC. It notes the zone and ufw's log level it found in `/etc/barely-free/node-tune.before`, and its header gives the way back for every change.
- **Connection tracking: 65,536 entries instead of 8,192** (added the same day, Lao: "Raise conntrack limit"). Every connection a device makes through the VPN goes through NAT and takes an entry; a full table drops new connections (sites hang), and the default on 1 GB of RAM was 8,192 (`nf_conntrack_max` = `nf_conntrack_buckets` = 8192). A phone holds tens to hundreds of connections and one torrent client thousands, so a few busy devices could fill it. It had never filled (0 "table full" lines in 3.4 days). `net.netfilter.nf_conntrack_buckets` and `nf_conntrack_max` are both 65,536, the kernel's own one-to-one ratio (its documentation: a full table then averages two entries per bucket, one per direction); that is about 512 KB of buckets and at most about 16 MB of entries (256 bytes each on these servers). These settings exist only once `nf_conntrack` is loaded, so `/etc/modules-load.d/bf-conntrack.conf` loads it at boot; `systemd-sysctl` runs after `systemd-modules-load`, so the lines are applied, not skipped. The servers' own file from before is kept as `99-vpn.conf.before-node-tune`.
- **UDP GRO forwarding** on the interface that reaches the internet: `ethtool -K <wan> rx-udp-gro-forwarding on rx-gro-list off`, at every boot from `bf-udp-gro.service` (a oneshot after `network.target`; the servers use ifupdown, not networkd-dispatcher or NetworkManager, the two hooks Tailscale's page describes). Where `ethtool -k` shows the feature `[fixed]`, the script leaves it out and says so.
- **`ufw logging off`.** The rules are untouched; only the log lines stop. It also means fewer internet addresses written to disk.
- **Clocks in UTC** (`Etc/UTC`). What moves on Dallas and Toronto (UTC, before and after; each timer keeps its random delay):

  | Timer or job | Before (IST clock) | After (UTC clock) |
  |---|---|---|
  | `bf-trackers-update.timer`, `logrotate.timer` (daily, up to 1 h late) | 18:30–19:30 | 00:00–01:00 |
  | `dpkg-db-backup.timer` (daily) | 18:30 | 00:00 |
  | `man-db.timer` (daily, up to 12 h late) | 18:30–06:30 | 00:00–12:00 |
  | `apt-daily.timer` (06:00 and 18:00, up to 12 h late) | 00:30 and 12:30 | 06:00 and 18:00 |
  | `apt-daily-upgrade.timer`, unattended-upgrades (06:00, up to 1 h late) | 00:30–01:30 | 06:00–07:00 (01:00–02:00 in Toronto) |
  | `fstrim.timer` (weekly) | Sunday 18:30 | Monday 00:00 |
  | `e2scrub_all.timer` (Sunday 03:10) | Saturday 21:40 | Sunday 03:10 |
  | `/etc/crontab` daily, weekly, monthly (06:25, 06:47, 06:52) | 00:55, 01:17, 01:22 | 06:25, 06:47, 06:52 |

  At the moment of the change, systemd runs once, at once, every `Persistent=true` timer whose time in UTC had already passed since its last run (on Dallas: the tracker update, logrotate, apt-daily, dpkg-db-backup, e2scrub_all; all finished in seconds). Harmless, and only the first time.

  Unchanged: `bf-logins.timer` (every minute), `systemd-tmpfiles-clean.timer` (a day after the last run), the hourly cron, and the VM's nightly backup (`OnCalendar=... 08:30:00 UTC`, on the VM, which is not touched).
- **unbound `serve-expired`** (RFC 8767), in `deploy/node-resolver.sh`: `serve-expired: yes`, `serve-expired-client-timeout: 1800` (fetch first; the stale answer, with unbound's 30 s reply TTL, is used only if the fetch takes over 1.8 s, the RFC's own figure and unbound's default since 1.23) and **`serve-expired-ttl: 3600`**, not the RFC's suggested 1 to 3 days. Quad9's malware block reaches devices as a failed lookup (SERVFAIL through validation, decision 022), and a failed lookup is exactly when unbound serves stale data: a name someone had already looked up, and that Quad9 then starts blocking, would keep resolving for as long as this window. An hour still rides through a short upstream outage. No query logging was added; `log-queries`, `log-replies` and the Quad9 forwarding are unchanged.
- **Kernel.** Each server reboots into the newest installed kernel, one server at a time, and the oldest kernel package (6.12.38) is removed with apt; the running kernel and the one before it stay as a fallback in GRUB. Toronto keeps 6.12.117 despite its new ITS W^X warning (below): the server works, and 6.12.116 is older; if a later Debian kernel still warns, nothing needs doing, and if Toronto ever misbehaves on 117, `grub-reboot` into 6.12.116 is the way back.

## Consequences
- A new server gets the same tuning by running `deploy/node-tune.sh` and `deploy/node-resolver.sh` (the README's node steps).
- Times in the servers' logs are UTC from 2026-11-15 on; older lines read in IST.
- The kernel no longer logs ufw's blocks, so a port scan leaves no trace on the server. Tailscale's policy and ufw's rules still decide what gets in; turning logging back on (`ufw logging low`) is the way to watch.
- `serve-expired` can hand out an answer up to an hour past its TTL when Quad9 is slow or down; a name newly blocked by Quad9 can stay reachable for that hour for devices on a server that had it cached.

## Measurements
Before (2026-11-15 ~05:50 UTC, both idle: load 0.0–0.1, about 570 MB free, swap unused, 7 peers on each interface and none connected):

| | Dallas (Xeon E5-2670 v2, AES-NI, no AVX2) | Toronto (Xeon Silver 4210, AVX2, AVX-512) |
|---|---|---|
| Download, Cloudflare, 3 × 25 MB | 260–418 Mbit/s | 412–449 Mbit/s |
| Download, Hetzner Ashburn, 100 MB | 43 Mbit/s | 371 Mbit/s |
| Upload, Cloudflare, 2 × 25 MB | 290–407 Mbit/s | 400–481 Mbit/s |
| `openssl speed -evp chacha20-poly1305`, 1 KB / 16 KB blocks | 295 / 330 MB/s | 521 / 615 MB/s |
| Ping to 1.1.1.1 | 1.6 ms | 0.9 ms |
| Kernel warnings today, not counting ufw | 1 (of 2,035) | 1 (of 2,041) |

The ports, not the CPUs, are the ceiling: one core encrypts ChaCha20-Poly1305 at 2.4 Gbit/s (Dallas) to 4.2 Gbit/s (Toronto), several times the port speed. The socket buffers and queue saw no drops (UDP receive-buffer errors 0, softnet drops 0), so no sysctl value changed. Toronto's `eth0` `rx_dropped` (155,088, about one every 2 s) most likely counts frames the kernel has no protocol handler for (link-layer chatter on the host's network; not confirmed with a capture), not lost traffic. Dallas's Hetzner download was slow on the path to Ashburn, not at the port.

After (2026-11-15 06:05–06:08 UTC, both on 6.12.117 with the tuning in force):

| | Dallas | Toronto (three runs) |
|---|---|---|
| Download, Cloudflare, 3 × 25 MB | 286–465 Mbit/s | 277–468 Mbit/s (one sample of 10) |
| Download, Hetzner Ashburn, 100 MB | 306 Mbit/s | 11, 358, 353 Mbit/s |
| Upload, Cloudflare, 2 × 25 MB | 270–406 Mbit/s | 99–101, 410/115, 415/578 Mbit/s |

No change beyond the paths' own variance, which is what was expected: these tests use the server's own TCP sockets, and UDP GRO forwarding only changes how forwarded UDP (users' QUIC and other UDP through the tunnel) is received. The number users feel needs a speed test through the tunnel; none was available while nobody was connected (0 devices on either server).

Kernel warnings after the reboot: the same set as the previous boot on each server (ACPI MMCONFIG, `systemd-ssh-generator` AF_VSOCK, `kauditd` callbacks; `awg-quick@.service is marked world-inaccessible` on Toronto), plus `hpet: Lost 2 RTC interrupts` on Dallas (a common virtual-machine boot line) and **one new warning on Toronto**: `CPA detected W^X violation` with a stack trace through `apply_retpolines` and `module_finalize`, raised while udev loaded modules on 6.12.117 (it taints the kernel `W`; 6.12.116 never showed it). The trace is the kernel's own permission self-check firing in the mitigation for Intel's Indirect Target Selection (ITS) flaw, which Toronto's Cascade Lake CPU takes and Dallas's does not; syzbot has reported the same warning upstream. Every check passed on both servers.

**How fast the ports really are** (later the same morning, after Lao's "you should have a 1 gig bandwidth"; read-only): the 25 MB single downloads above are too short to fill a fast port, so the ports were measured with streams in parallel. Eight downloads at once from Cloudflare: Dallas 397 Mbit/s, Toronto 214 Mbit/s. Four at once for 8 s from OVH in Beauharnois, Canada: Dallas 582 Mbit/s, Toronto 595 Mbit/s; from Hetzner in Ashburn: 350 and 342 Mbit/s. Four uploads at once to Cloudflare: 121 and 286 Mbit/s. The CPU stayed at least 65% idle with about 2% steal throughout. So each port carries at least about 600 Mbit/s on a good route and less on others; the ceiling is the host's network and the route, not a setting on the server or its CPU. A "1 Gbit/s port" on a plan like this is usually shared.

**How fast one vCPU can push WireGuard** (Lao: "also do these", 2026-11-15 ~07:40 UTC): a WireGuard tunnel between two network namespaces on each server, joined by a veth cable, with `iperf3` through it (installed for the test and purged after; `wg0`, `awg0` and the firewall untouched; nobody connected). A plain veth carries 4.6–5.0 Gbit/s; through WireGuard:

| | 1 TCP stream | 4 streams | reverse |
|---|---|---|---|
| Dallas (Xeon E5-2670 v2) | 236 Mbit/s | 208 Mbit/s | 226 Mbit/s |
| Toronto (Xeon Silver 4210) | 488 Mbit/s | 366 Mbit/s | 433 Mbit/s |

Here the one vCPU encrypts and decrypts every packet (both ends are on it), so these are lower bounds; a real server does one of the two per packet, plus forwarding and NAT, so its ceiling sits between these figures and about twice them. Dallas's CPU is therefore the likely limit for its users (roughly 250–450 Mbit/s, under its ~600 Mbit/s port); Toronto's keeps up with its port. A newer CPU or a second vCPU for Dallas is the change that would raise it.

What that means for users: BBR, `fq` and the socket buffers change only the server's own TCP connections (DNS over TLS to Quad9, apt, the speed tests). A device's traffic through the tunnel is forwarded, so its TCP is between the device and the site; the server cannot speed it up with settings. What limits a user is, in order: their own connection and distance, the route from the server, the port (about 350–600 Mbit/s measured) and one vCPU doing every user's encryption (ChaCha20-Poly1305 at 2.4 Gbit/s on Dallas and 4.2 Gbit/s on Toronto per core in OpenSSL; kernel WireGuard also pays per-packet costs, so the real tunnel ceiling is lower and was not measured). Faster than this needs a bigger plan (more vCPUs) or a host with a dedicated gigabit port.

## Not in this decision
- A second hosting company (the fix for the single-provider outage of 2026-11-11 and the only way to IPv6), a bigger plan or newer CPU for Dallas, and client-side MTU changes.

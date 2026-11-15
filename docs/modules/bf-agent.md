# bf-agent
**Status:** Implemented — deployed, idle, on Toronto and Dallas (2026-11-09).

## Overview
The node agent: answers two signed requests on localhost and keeps WireGuard matching the last peer list it was given. The contract is `specs/agent.md`.

## Key details
Code map, `crates/bf-agent/src/`:
- `main.rs`: `bf-agent` (the service), `bf-agent probe` and `bf-agent trackers build <list> <allow file> <zone file>`.
- `log.rs`: the only way to write a log line. `eprintln!` panics when stderr is closed, so clippy denies it here.
- `server.rs`: axum; one fallback handler takes every request, 1 MiB body limit, work goes to `spawn_blocking`.
- `service.rs`: `Agent::handle_with(clock, load1, &Request) -> Reply` (auth, routing, status, `PUT /v1/peers`), `Agent::reconcile()`, and `keep_matching`, the pass on start and every 30 s.
- `reconcile.rs`: `apply(wg, &desired)` reads the dump, plans, then removes, updates, adds. `forget_idle(wg, &desired, now, after, &mut quiet)` removes a listed peer and sets it again with its ranges from the list. It does so when the peer has an endpoint, no handshake in the last `after` seconds, and looked exactly the same at the last pass (`Quiet`: address held, handshake, rx). WireGuard then no longer holds its address, handshake time or byte counts (decision 020). `Agent::forget_idle` runs it at the start of every 30-second pass, before the list pass, which puts back a peer whose re-add failed. It uses `bf_common::wg::FORGET_IDLE_AFTER_SECS` (300), only while a list is stored, under the `changing` lock. It logs only a count ("forgot 2 idle device(s)"). `BF_ONLINE_SECS` must be under 300.
- `wgcli.rs`: the `Wireguard` trait (`dump`, `remove_peer`, `set_peer`) and `WgCli`, which runs `wg` with a 10 s deadline and kills it past that. `run_program` is the shared runner (deadline, both pipes drained, optional standard input, first stderr line only in errors).
- `nft.rs`: the tracker switch (`specs/trackers.md`): the `TrackerSet` trait and `NftSet`, which replaces the set `inet barely_free_dns off_<interface>` whole in one `nft -f -` transaction (`flush set` plus `add element`).
- `trackers.rs`: `build(list, allow, zone)` behind `bf-agent trackers build`: reads the downloaded EasyPrivacy and the allow file, applies the floor against the zone in force, writes the zone through `<zone>.tmp` and a rename (mode 0644, for unbound).
- `store.rs`: `peers.json` and `replay-mark` in the state directory, each replaced atomically, mode 0600 (the list is synced to disk; the mark is not, because it is written on the way to answering a request).
- `config.rs`, `secret.rs`: `BF_*` settings and the hex secret file.
- `client.rs`: the blocking HTTP client behind `probe` and the tests.
- `logins.rs` (decision 023): the `LoginLog` trait and `LoginFiles`, which reads `logins` and `login-keys` from the folder `bf-logins.timer` writes (`/var/lib/barely-free-logins`) through `bf_common::logins::from_files`. A missing, unreadable or stale (over 5 minutes) file is an error.
- `testutil.rs` (tests only): `FakeWg`, `FakeSet` (a recording tracker switch that can be told to fail), `TempDir`, key fixtures.

Behavior worth knowing:
- Replay mark (decision 007): `Agent::new_at(.., started_at)` reads `replay-mark` and gives the verifier that time as its floor; every accepted request writes the new highest time first. A restart therefore refuses copies of anything accepted before it, and also anything legitimate signed at or before the mark (the caller signs a later one). No file: floor = start time. Unreadable file: floor = start time + 60 s. Delete `replay-mark` if the node's clock went backwards by a lot and the control program is locked out. `Agent::new` (floor 0 unless a mark exists) is for tests.
- Three locks: `verifier` (held only while a signature is checked), `stored` (held only to read or replace the list) and `changing` (PUT and the reconcile pass take turns, across `wg` calls). Status takes none while it talks to `wg`, so a slow change never holds up refusals or status. The server passes the clock to the agent, which reads it after taking the verifier lock.
- Tests: unit tests per module, real-socket tests in `server.rs`, and `tests/cli.rs`, which runs the built binary against a fake `wg`. Against a real WireGuard: `deploy/node-selftest.sh` on a node.
- On the node: `deploy/bf-agent.service` (dynamic user, `CAP_NET_ADMIN` only, localhost only), `/etc/barely-free/agent.secret`, state in `/var/lib/barely-free`.
- A server with both protocols (`specs/dual-protocol.md`) runs a second agent, the same binary: `bf-agent-<protocol>.service` on `127.0.0.1:9871` for the other interface (`wg0` with `/usr/bin/wg`, or `awg0` with `/usr/bin/awg`), secret `/etc/barely-free/agent-<name>.secret`, state `/var/lib/barely-free-<name>`, made by `deploy/node-add-protocol.sh` from the first unit, and reached through Caddy as `<name>.agent.internal:8443`. `deploy/node-selftest.sh` uses port 9879 for its scratch agent so it never collides with that. `deploy/node-dual-selftest.sh` checks one client key on both interfaces. `deploy/deploy-agent.sh` keeps the interface each server's first agent drives (it reads `BF_INTERFACE` from the installed unit, so Toronto stays on `awg0`) and restarts the second agent after installing the binary. Each interface also takes extra UDP ports (WireGuard 53 and 123, AmneziaWG 4500), redirected by the firewall to its own port (`deploy/node-extra-ports.sh`); the agent does not see them. The agent knows nothing of server locations or "Closest to you": that is the website's choice when a device is made (decision 014).
- Logins in the status (decision 023): every status carries `logins`, the server's SSH logins of the last 15 minutes. The agent cannot read the journal or `/root/.ssh` (dynamic user, `ProtectHome=yes`), so a root timer, `bf-logins.timer`, writes them once a minute into `/var/lib/barely-free-logins`, and `deploy-agent.sh` puts every agent in the group `bf-logins` that may read it (drop-in `bf-agent*.service.d/logins.conf`, `SupplementaryGroups=bf-logins`; the group is made first, because an agent naming a missing group would not start). When the files cannot be read or are stale the field is left out, and the failure is logged once when it starts and once when it ends. `BF_LOGINS=off` switches it off; `BF_LOGINS_DIR` moves the folder. Checked on Dallas with `systemd-run`: an agent-like sandbox reads the files with the group and is refused without it. A second agent made later by `node-add-protocol.sh` gets the drop-in at the next `deploy-agent.sh`.
- Attention in the status (decision 031): `LoginLog::attention` (implemented by `LoginFiles`) reads `/var/lib/barely-free-logins/attention`, written hourly by `bf-attention.timer` (`deploy/bf-attention.sh`), and the status carries it as `attention` (reboot flag and its packages, updates waiting, parsed by `bf_common::attention::from_file`); no file, or one older than three hours, means no field (the latter logged once).
- `deploy-agent.sh` opens three SSH connections: the binary, one tar with the unit and the login timer's files (unpacked into a fresh 0700 folder as root's files), and the remote part. The nodes' ufw allows an address 6 new SSH connections in 30 s, so keep it at three (`tests/logins_script.rs` counts them); through a VPN client's tunnel a refused connection looks like a reset during the key exchange.
- Tracker switch (`BF_TRACKERS=nft`, decision 015): after each list it applies, and on every 30-second pass, the agent writes the IPv4 `/32` addresses of the peers with `trackers: false` into its set. A failure never changes a PUT's answer; it is logged once when it starts ("trackers: cannot update the switch") and once when it ends, and the next pass tries again. With the setting unset the agent never runs `nft`. `deploy/node-resolver.sh` makes the table, the sets and the rule, and adds the setting to every agent through a drop-in (`bf-agent*.service.d/trackers.conf`).

## HTTPS in front (decision 006)
- Caddy on each node listens on `:8443` as `<node>.agent.internal` (`toronto`, `dallas`) with `tls internal`, and proxies to `127.0.0.1:9870`. The name is in no DNS: the caller connects to the node's IP and sends the name as SNI. No SNI, another name or plain HTTP gets no certificate or Caddy's 400.
- The caller trusts only that node's root: `deploy/node-roots/<node>.pem` (public). Reinstalling a node makes a new root; replace the file (`deploy/node-roots/README.md`).
- Install or update: `deploy/deploy-caddy.sh root@<node ip> <node> -i ~/.ssh/<key> -o IdentitiesOnly=yes`. It adds two imports to `/etc/caddy/Caddyfile` (backup at `Caddyfile.before-bf-agent`), validates as the `caddy` user, opens `8443/tcp` in ufw (`BF_CONTROL_IP=<addr>` limits it to one address), reloads, and puts the backup back if Caddy will not start. `BF_UNDO=1` takes it out again.
- Check: `ssh <opts> root@<node ip> 'sh -s -- <node> <node ip>' < deploy/node-tlscheck.sh` (14 checks: certificate and root, TLS 1.2+, no SNI or wrong SNI refused, unsigned 404, signed status through TLS, plain HTTP, port 9870 closed, slow header and body cut off, holding page unchanged). It changes nothing.
- Caddy cuts off slow headers after 5 s and slow bodies after 15 s; the agent's own 10 s body limit is the second line.

## API / interfaces
`GET /v1/status`, `PUT /v1/peers`, the signing headers and every answer: `specs/agent.md`.

## Dependencies
bf-common; axum 0.8 (http1 only), tokio (rt, macros, net, time, sync), serde, serde_json. Needs `wg` on the node and `CAP_NET_ADMIN`; with the tracker switch on, also `nft` (Debian's nftables package, 1.1.3 on both nodes).

## Known issues / gotchas
- One `wg` process runs per changed peer, so a first list of thousands of peers takes seconds.
- No TLS or rate limiting of its own: it sits on localhost and Caddy is in front on port 8443 (see "HTTPS in front" above). A stalled request body is cut off after 10 s, but slow request headers are not (axum's `serve` has no header timeout), so Caddy's timeouts matter; they are set in `deploy/caddy/agent.global`.
- The error text from `wg` (first line of its stderr) is logged and can reach an answer; it names keys and interfaces, never secrets.

## Test helpers for other crates
The agent's fake `wg` and temporary-directory helpers (`bf_agent::testutil`) are compiled for its own tests and, with the Cargo feature `testing`, for other crates' tests: `bf-control` enables it as a dev-dependency to run the real agent behind its poller tests. The shipped agent is unchanged.

## Related
- [bf-common](bf-common.md)
- [The agent drives `wg`](../decisions/001-wg-program.md), [Signed requests](../decisions/002-signed-requests.md)
- [Agent TLS with Caddy's own CA](../decisions/006-agent-tls-with-caddys-own-ca.md), `research/tls/RESEARCH.md`
- [Tracker blocking on the servers](../decisions/015-tracker-blocking-on-the-servers.md), `specs/trackers.md`
- `specs/agent.md`, `deploy/`

# 015: Tracker blocking on the servers: unbound, a strict EasyPrivacy, and a firewall switch per device
**Date:** 2026-11-10
**Status:** Accepted (Lao, 2026-11-10: "Approve, trackers first")

## Context
The front page promised that known trackers are blocked by default, that the owner can switch this off per device, and that ads are not blocked. Device files sent DNS to `1.1.1.1`. Every server has two in-tunnel addresses since decision 013: `10.77.0.1` (AmneziaWG) and `10.78.0.1` (WireGuard), each with its own agent. The agents run sandboxed: a dynamic user, only `CAP_NET_ADMIN`, `ProtectSystem=strict`. The nodes run Debian 13 with AppArmor on and `nft` 1.1.3. Research: `research/trackers-and-closest/RESEARCH.md`.

## Decision
- **unbound on each server**, from Debian (1.26.2). It answers only on localhost and the two in-tunnel addresses (`ip-freebind`, so it starts before the interfaces). It forwards to Cloudflare over TLS, and logs no queries.
- **Two ports, one tag.** Port 53 carries the tag `trackers`, which the RPZ zone is limited to. Port 5300 has no tag. It is chosen by `interface-tag <address>@<port>`, never by `access-control`, which would override the interface tags (unbound manual). Not 5353: that is the mDNS port.
- **The switch is the firewall's, not unbound's.** Each agent keeps an nftables set `inet barely_free_dns off_<interface>` of its devices whose blocking is off. A rule `dnat`s their port-53 traffic to port 5300 of the same in-tunnel address, named in the rule: `redirect` would pick the interface's first address, which on Dallas's `wg0` is the old `10.66.2.1` (found by the code review; `nft -c` accepted the rules on both nodes). The agent writes the set whole in one `nft -f -` transaction after each list and on every 30-second pass. A switch takes effect at once with no unbound reload. It fits the agent's sandbox, and a reboot heals within a pass. The node's setup script owns the table and the rule; the agents only fill their sets.
- **The switch travels in the peer list.** Each peer gains `trackers`. A missing field means on, and on is never written, so lists of filtered devices keep their exact text and version. Older agents ignore the field.
- **The list is EasyPrivacy, read strictly.**
  - Kept: only exact `||name^` rules. Rules with options (`$third-party` above all) cannot be honoured by DNS, and blocking them would break first-party use.
  - Exempted: an exact `@@||name^` rule, or a line of the allow file, frees the name, every name under it, and any blocked name above it.
  - Names need two labels and a non-numeric last label, so `||com^` or an IP address can never become a block.
  - The node fetches the list daily and converts it with `bf-agent trackers build`. A result under 1,000 names, or under half the zone in force, is refused and the old zone stays.
- **No poke per switch.** The website's switch changes the row and waits for the poller's next pass (10 s). A poke per press would let anyone signed in drive a pass a second, and every pass moves each node's signing time one second ahead per request.
- **Names fit the zone.** At most 226 characters, so `*.<name>.trackers.rpz.barely-free.` stays within DNS's 255 bytes; one longer name would make unbound refuse the whole zone.
- **DNS in the files.** A device's DNS is the first address of its `/16`, so the file needs no knowledge of the server: `10.77.0.1` for AmneziaWG, `10.78.0.1` for WireGuard.
- **Devices that set their own DNS are not intercepted.**

## Consequences
- A DNS outage on a server takes name resolution away from its devices, because the files name only that server.
- Devices made before the website deploy keep `1.1.1.1` and are unfiltered until made again.
- The zone lives in `/var/lib/unbound/`, which Debian's AppArmor profile lets unbound read.
- `deploy/deploy-agent.sh` keeps a node's own unit file now. Toronto's holds its `awg0` settings, and the old script would have overwritten them.
- It is not yet proven on a node that `interface-tag` on `@53` and `@5300` gives the two ports different tags. `deploy/node-resolver.sh` checks it at its end with a listed name that exists upstream, and exits 1 if 5300 blocks it too. The fallback is `/32` access-control exceptions plus a reload.
- Not covered by the setup script's own checks: the redirect of a real device whose switch is off, because a local query does not pass the prerouting hook. Check it with a device.

## Related
`specs/trackers.md`, decisions 003, 009, 013, 014 (the closest server, the other half of the brief), `docs/modules/bf-agent.md`, `docs/modules/bf-control.md`

## Amended 2026-11-12
unbound now forwards to Quad9 instead of Cloudflare (decision 022), which also refuses names known to spread malware, on both ports.

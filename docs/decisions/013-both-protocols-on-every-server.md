# 013: Both protocols on every server: two address ranges, one agent per interface
**Date:** 2026-11-10
**Status:** Accepted (Lao, 2026-11-10: "Yes, build it")

## Context
Lao asked for WireGuard and AmneziaWG on both servers and a quick way to get each app. Toronto ran only AmneziaWG (`awg0`) and Dallas only WireGuard (`wg0`), both on `10.77.0.0/16`, and every device is a peer on every node (decision 004). Research: `research/dual-protocol/RESEARCH.md`.

## Decision
- **Two ranges, one device.** AmneziaWG keeps `10.77.0.0/16`, so today's devices keep working; WireGuard uses `10.78.0.0/16`. A device keeps its one allocated address, and on WireGuard it is the same last two numbers. Two interfaces on one server cannot hold the same subnet, so a split was needed; mapping one to one means no change to `devices`, no migration of devices, and every device is valid on all four interfaces. The person picks server and app when adding it.
- **One agent per interface, not one agent for two.** The agent already drives either `wg` or `awg`; a second instance per server needs no agent code change and keeps the two interfaces independent. Each is a registry node with a `protocol` (schema 5).
- **Same port, told apart by name.** Both agents of a server sit behind Caddy's `:8443` with their own `<name>.agent.internal`; no firewall change on the servers or on the web VM's guard. So `nodes.address` is no longer unique on its own.
- **The poller maps, the agent does not know.** A WireGuard agent is sent the published list with `10.77.a.b/32` moved to `10.78.a.b/32`, same version.
- **Unset is today.** A node from before schema 5 has no protocol: it gets the list as published (exactly as before) and is offered for nothing until `node set-protocol`. A deploy therefore changes nothing on the wire.
- **AmneziaWG from Amnezia's archive, pinned to its full key, kernel module only.** No Debian series exists; the Ubuntu one is used with a `signed-by` keyring; the setup refuses to continue without `/sys/module/amneziawg` (no silent userspace fallback).

## Consequences
- Two secrets, two units, two registry rows per server.
- One client key on both interfaces of a server is not proven by any published source; `deploy/node-dual-selftest.sh` must pass on a server before its second protocol is offered.
- Every kernel upgrade needs the AmneziaWG module rebuilt (DKMS).
- Today's AmneziaWG devices keep their addresses; anyone holding an old plain-WireGuard file for Toronto (before its switch) already had one that did not work.

## Related
`specs/dual-protocol.md`, decisions 004, 006, 009, `docs/modules/bf-control.md`, `docs/modules/bf-agent.md`

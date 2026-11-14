# 001: The agent drives WireGuard through the `wg` program
**Status:** Accepted — 2026-11-09

## Context
The agent must read peers and change them without disturbing the ones that stay. The options were a Rust crate that talks to the kernel (`defguard_wireguard_rs`, netlink crates) or the `wg` program that ships with WireGuard.

## Decision
Use `wg show <if> dump` to read and `wg set <if> peer <key> allowed-ips ...` or `... remove` to change. Add and update are the same command.

## Consequences
- `wg` is the documented interface and the same thing an operator would type, so what the agent does can be checked by hand.
- Tests swap in a fake: a shell script for `WgCli`, and `FakeWg` for everything above it.
- `wg set peer` touches one peer, so nobody else is disconnected (checked on a real interface).
- Cost: one process per changed peer. A batch path (`wg syncconf`) can replace it later.
- The dump holds secrets, so the parser drops them on read.

## Related
- [bf-agent](../modules/bf-agent.md)

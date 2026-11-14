# 003: Peer lists are checked strictly and applied by difference
**Status:** Accepted — 2026-11-09

## Context
A mistake in the list the control program sends can silently hand one device too much, or make two devices fight over an address. The spec only required valid keys and `address/prefix`.

## Decision
The agent refuses the whole list (400, nothing changes) when a key is not canonical base64, a range has bits set below its prefix (`10.77.0.5/24`), a key appears twice, or two peers hold the same range. It then changes only what differs: removals first, then updates, then additions.

## Consequences
- A peer can never claim more than its list entry says, and two peers cannot take an address back and forth on every 30-second pass.
- Ranges are compared as parsed values, so `FD00:0:0::2/128` and `fd00::2/128` are the same range.
- Removing first means a kick lands before anything else in the same list.
- The control program must send exactly `/32` and `/128` ranges (or clean subnets), which it does anyway.
- An empty list is valid and removes every peer; the control program is trusted not to send one by mistake.

## Related
- [bf-common](../modules/bf-common.md), `specs/agent.md`

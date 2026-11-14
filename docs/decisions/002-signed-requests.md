# 002: Requests are signed with a shared secret, not sent over mutual TLS
**Status:** Accepted — 2026-11-09

## Context
The control program on the web VM calls each node. It has to prove who it is, a captured request must not work twice, and the node must hold nothing that lets it act as the control program.

## Decision
Every request carries `X-BF-Time`, `X-BF-Nonce` and `X-BF-Sig`: HMAC-SHA256 over method, path with query, time, nonce and the body's SHA-256, under a per-node secret. Accepted only within 60 seconds of the node's clock and once per nonce. Anything that fails gets the same empty 404 as an unknown path. The agent itself speaks plain HTTP on localhost; Caddy adds TLS in front.

## Consequences
- Small to implement and test; vectors from Python's `hmac` and a second implementation in `openssl` and `curl` agree with it.
- A scanner learns nothing: there is no difference between a wrong path and a wrong signature.
- Each node has its own secret, so one stolen secret opens one node. It also means the control program must hold every node's secret.
- The replay cache lives in memory, so a restart forgets it. That gap is closed by the replay mark, which refuses everything signed at or before the highest time accepted before the restart ([007](007-replay-mark-across-restarts.md)).
- Clocks on the control VM and the nodes must stay within a few seconds of each other.

## Related
- [bf-common](../modules/bf-common.md), [bf-agent](../modules/bf-agent.md)

# Architecture
**Status:** Partial — the node agent runs on both nodes; the control program has its website deployed and its database and admin commands built (step 2, first part). It does not talk to the nodes yet.

## Overview
Three servers. A control program on the web VM decides who may connect. An agent on each VPN node (Dallas, Toronto) reports WireGuard's state and applies the peer list it is given. VPN traffic runs through the kernel's WireGuard and never through our code.

## Module boundaries
| Module | Responsibility | Depends on |
|---|---|---|
| `bf-common` | Parse `wg show dump`, build the status, check and plan peer lists, sign and verify requests | nothing of ours |
| `bf-agent` | Node service: two signed requests on localhost (Caddy puts HTTPS in front on port 8443, decision 006), `wg` calls, the stored list, the reconcile loop | `bf-common`, `wg` |
| `bf-control` | Today: the website, the SQLite database (accounts, devices, kicks), key generation, the admin command line, and the peer list worked out from the database and the time. Planned: polling and pushing to the nodes, admin panel, steering | `bf-common` |

## Data flow
1. The control program signs a request and calls a node. The web VM has no inbound ports, so calls only go outward.
2. `GET /v1/status`: the agent reads `wg show dump` and answers with online counts, handshake ages and masked client addresses. If WireGuard cannot be read it says "unavailable", never zero.
3. `PUT /v1/peers`: the agent checks the list, writes it to disk, then removes, updates and adds only what differs. On start and every 30 seconds it makes the same pass again from disk.
4. If the control program is off, each agent keeps enforcing its last list.
5. Where the list comes from (built, not yet connected to step 1): an admin adds accounts and devices and kicks with `bf-control`; `publish(now)` turns the devices and kicks at that moment into a `PeerList` whose version rises only when the list changes. The poller (next) will call it and sign a `PUT /v1/peers` to each node.

## Key decisions
- [001 the `wg` program](decisions/001-wg-program.md)
- [002 signed requests](decisions/002-signed-requests.md)
- [003 strict peer lists](decisions/003-strict-peer-lists.md)
- [004 the list is worked out from the database and the time](decisions/004-list-from-database-and-time.md)
- The reasoning for the whole plan: `research/rebuild/RESEARCH.md`

## Diagrams
The shape is drawn in `research/rebuild/RESEARCH.md` ("Shape"). Code locations: [modules/bf-agent.md](modules/bf-agent.md).

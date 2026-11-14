# 008: The poller pins each node with reqwest, keeps node secrets in files and readings in memory
**Status:** Accepted — 2026-11-10 (Lao approved `specs/poller.md`: schema 3, the dev-only test dependencies and the defaults)

## Context
Decision 006 said the control program must trust only a node's own root, send the node's name as SNI, and that "prefer a verifier that is known to ignore the public roots" would be a new dependency needing approval, because reqwest's handling of "no built-in roots" was disputed in older versions. The poller also needs each node's signing secret and somewhere to keep what it learns.

## Decision
- **Pinning with the HTTP client already in the tree.** `reqwest` 0.13.5 (the Resend client's) has `ClientBuilder::tls_certs_only`. In its source (`src/async_impl/client.rs`, the rustls branch) the platform verifier is used only when `tls_certs_only` is not set; with it the config is `with_root_certificates` of a store made from the given certificates alone, the ordinary WebPki verifier, which also checks the name. So no new runtime dependency. One client per node: that node's root only, `resolve` sends `<name>.agent.internal` to the registered address (the name is what is verified and sent as SNI), HTTPS only, no redirects, no proxies, HTTP/1.1.
- **Checked three ways.** Tests against a local TLS server with a Caddy-like chain (root, intermediate, leaf) refuse another authority, another name, an expired leaf, a self-signed leaf and plain HTTP; the same code was run against the real Toronto and Dallas nodes (2026-11-10): both accepted their pinned root and answered a made-up secret with the agent's 404, and Toronto refused Dallas's root. One thing cannot be tested offline: that a root the system trusts but we did not pin is refused; it rests on reading the source.
- **A node is a row; its secret and root are files.** `nodes` (schema 3) holds name, title, place, address, enabled. `<BC_NODES_DIR>/<name>.secret` (hex, owner-only, the rules of the other key files) and `<name>.pem` are read again on every pass, so a replaced file needs no restart and a database backup never carries a signing key. The names are checked again before they become part of a path.
- **Readings stay in memory.** The poller keeps, per node, health, last good time and the last status's counts and per-device online flags; the masked client address is dropped on reading. Nothing is written to disk. A restart forgets them and the site says "Status unknown" until the first pass (a few seconds).
- **Failure never looks like zero.** A pass that did not get a status has no reading. A node is "Not responding" after 3 failed passes in a row, back online after one success. A board older than 60 s reads as unknown.
- **Every request to a node is signed later than the one before it** (`max(now, previous + 1)`, kept across a rebuilt link), so the replay mark of decision 007 can never refuse the poller's next request.
- **One list for all nodes; push only on a version mismatch.** A node that holds a higher version than the database (a restored backup) is flagged "ahead" and sent nothing. `bf-control list raise <n>` is the manual remedy; it is never done automatically because a damaged or hostile node could otherwise push the versions up.
- **The poller starts only if the database already exists** and a broken node never stops the website.
- **The secrets move by Lao's hand.** `deploy/set-node-secret.sh` pipes the secret from the node to the VM through Lao's own ssh; it is never in a variable, on a command line, on screen or in a file on the Mac, and only the first 8 characters of its SHA-256 are printed at each end.

## Consequences
- New runtime dependencies: none. Dev-only: `rcgen` 0.14.10 (`aws_lc_rs`, `pem`), `rustls` 0.23.46 and the workspace's own `bf-agent` (through a new `testing` feature that exposes its fake `wg` helpers); none is in the shipped binary (`cargo tree -e normal`).
- A node reinstalled gets a new Caddy root; until `deploy/node-roots/<name>.pem` is replaced on the VM its card reads "Not responding" and `bf-control node check <name>` says the certificate was not accepted.
- The poller and the website share one process; a hung node costs a task for at most 20 s. One database, one poller: running two servers on the same database would send the same lists twice (harmless, wasteful).
- A node that holds the same version number but a different list is not noticed (only after a restored database and luck); comparing key sets was left out because the agent's own pass lags by up to 30 s.

## Alternatives rejected
- **A hand-written rustls verifier:** more security-sensitive code of our own and a new direct dependency for the same pin.
- **Secrets in the database:** every backup would carry every node's key.
- **A status table:** a second schema change and per-device activity on disk that nobody needs.
- **Raising the version automatically when a node is ahead:** lets a lying node move the numbers.

## Related
- [002 Signed requests](002-signed-requests.md), [006 Agent TLS](006-agent-tls-with-caddys-own-ca.md), [007 Replay mark](007-replay-mark-across-restarts.md), `specs/poller.md`, `research/poller/RESEARCH.md`, [bf-control](../modules/bf-control.md)

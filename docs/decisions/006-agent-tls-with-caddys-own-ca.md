# 006: The agents are reached over HTTPS from Caddy's own CA, pinned per node
**Status:** Accepted — 2026-11-10 (Lao chose route A from `research/tls/RESEARCH.md`)

## Context
Signed requests (decision 002) authenticate the control program and protect the body from tampering and replay, but they send everything in the clear. On the open internet that shows anyone on the path every device's public key and tunnel address (`PUT /v1/peers`) and, per key, online state, traffic and a masked client address (`GET /v1/status`). The agent also has no timeout for slow request headers.

## Decision
- Caddy on each node listens on **port 8443** and passes requests to the agent on `127.0.0.1:9870`. The site name is `<node>.agent.internal` (for example `toronto.agent.internal`). The name exists nowhere in DNS: the control program connects to the node's IP address and sends that name as the server name (SNI).
- The certificate comes from **Caddy's own local CA** (`tls internal`). Each node has its own root. The control program trusts **only that node's root for that node** (a pin). The node's public CA store is not involved, and the node does not add its own root to its system trust store (`skip_install_trust`).
- The node's root certificates are public and live in `deploy/node-roots/<node>.pem`. A node that is reinstalled makes a new root, so its file must be replaced.
- HMAC signing stays. TLS adds secrecy and a timeout layer; it does not replace the signature check. Mutual TLS was not added.
- Caddy cuts off slow clients (`read_header 5s`, `read_body 15s`, `write 30s`, `idle 30s`, `max_header_size 8KB` on `:8443`). The holding page on ports 80 and 443 is untouched.
- Port 8443 is open to everyone by default, because the web VM's address is a home connection that can change. `BF_CONTROL_IP` limits it to one address.

## Consequences
- No DNS record, no outside CA, no Caddy upgrade, and no change to the agent or its privileges. Nothing in the Rust code changed.
- Without SNI, or with another name, the handshake fails, so a scanner learns nothing from the certificate. Plain HTTP on 8443 gets Caddy's 400 and never reaches the agent.
- Caddy renews the 12-hour leaf and the 7-day intermediate by itself. The root lasts until 2036 (Toronto and Dallas: 2036-09-18).
- The control program's HTTPS client (step 2, second part) must build its trust store from the one pinned root, send the node's name as SNI and, because that library's handling of "no built-in roots" is disputed (reqwest issues), prefer a verifier that is known to ignore the public roots. That is a new dependency and gets its own approval.
- The nodes run Caddy 2.6.2 from the Debian package (2022). Nothing here needs a newer one, but it sits on the public internet and should be replaced with a current release.
- HTTP/3 is switched on by Caddy for 8443 by default; the firewall opens TCP only, so it is not reachable.

## Alternatives rejected
- **Let's Encrypt on node hostnames:** a normal certificate, but two DNS records from the owner of the barely-free.com Cloudflare account, and renewal depends on port 80 and DNS.
- **Let's Encrypt IP-address certificates:** shortlived profile only, experimental in Caddy, and the Caddy release that fixes IPv6 was not found.
- **TLS inside the agent (rustls):** more attack surface in the one process that holds `CAP_NET_ADMIN`, and the header timeouts would have to be built.
- **Mutual TLS:** the signature already authenticates the caller; a second secret to rotate buys nothing now.

## Related
- [002 Signed requests](002-signed-requests.md), [bf-agent](../modules/bf-agent.md), `research/tls/RESEARCH.md`
- `deploy/deploy-caddy.sh`, `deploy/caddy/`, `deploy/node-tlscheck.sh`, `deploy/node-roots/`

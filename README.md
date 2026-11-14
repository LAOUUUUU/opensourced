# Barely-free: public source copy

This is a public, scrubbed copy of the source of [Barely-free](https://barely-free.com), a free VPN built on WireGuard (this copy is version 0.5.0). It holds the Rust code (the node agent `bf-agent`, the control program and website `bf-control`, and the shared library `bf-common`), the deploy scripts and the design notes.

- Addresses, host names and personal details are placeholders (`<vm ip>`, `<your-tailnet>.ts.net`, and documentation-range addresses in scripts and tests). **This is not a drop-in deployment of the live service**; the runbooks below describe how the live one is set up.
- The private working notes, research briefs and specs are not part of this copy, so a few links below point at files that are not here.
- Licensed under the MIT License (see `LICENSE`).
- To report a security problem, use the contact on <https://barely-free.com/security>.

---

# Barely-free

A free VPN for anybody, on WireGuard, written in Rust. This is the ground-up rebuild of the old Python build (`happ-vpn`), which keeps serving its 35 keys until this one replaces it.

**Status (2026-11-10):** step 1 of 7 is done, and step 2 is built: `bf-control` has a database, an admin command line (accounts, devices, kicks, the peer list), sign-in pages (off until configured) and a **node poller** that keeps the nodes' WireGuard in step with the database and shows each server's state on the front page. The poller, sign-in and the add-a-device page are deployed to the web VM and work with both nodes; release 0.3.0 (the admin panel, cookies, the plainer design and the kick fix) is deployed there too, and the **admin panel** (`/admin`) stays hidden until an account is made admin and given its password. The node agent `bf-agent` runs on both VPN nodes (Dallas and Toronto). The public website (a closed-beta front page, served by `bf-control`) runs on the web VM and is waiting only for DNS to go public.

## How it fits together
- A **control program** (`bf-control`, partly written) on the web VM decides who may connect: accounts, devices, the admin panel, counts, kick, steering to the closest node.
- An **agent** (`bf-agent`) on each VPN node reports WireGuard's state and applies the peer list it is given. VPN traffic never goes through our code; it runs through the kernel's WireGuard.
- The control program calls the agents, never the other way round (the web VM has no inbound ports). If it is off, the VPN keeps working on the last list each agent has.

The plan, the choices and the reasons are in [research/rebuild/RESEARCH.md](research/rebuild/RESEARCH.md). What the agent promises is in [specs/agent.md](specs/agent.md).

## Layout
| Path | What |
|---|---|
| `crates/bf-common` | Shared library: reads `wg show dump`, builds the status, checks and plans peer lists, signs and verifies requests |
| `crates/bf-agent` | The node agent: HTTP service on localhost, the `probe` command, the tracker switch, and `trackers build` (the tracker list for the node's resolver) |
| `crates/bf-control` | The control program: the public website (pages in `web/`, built into the binary), the database and the admin command line |
| `deploy/` | `tailscale-join.sh`, `tailscale-policy.hujson`, `tailscale-archive-keyring.gpg` and `node-tailnet-guard.sh` (SSH through Tailscale, decision 024), `bf-agent.service` (systemd), `deploy-agent.sh`, `node-selftest.sh` (checks a build against a real WireGuard on a node), `deploy-caddy.sh` with `caddy/` (HTTPS in front of the agent), `node-tlscheck.sh` (checks that HTTPS), `node-roots/` (each node's public root certificate), `node-resolver.sh` (the node's DNS with tracker blocking), `bf-logins.{sh,service,timer}` (each server's recent SSH logins for the login alerts, installed by both deploy scripts) and `seed-known-logins.sh` |
| `docs/` | Module docs, decision records, architecture and current state; start at `docs/TABLEOFCONTENTS.md` |
| `specs/` | Specs, written before the code |
| `research/` | Research briefs |

## Build and test
Needs stable Rust. No WireGuard is needed on the Mac: the tests use a fake `wg`.

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Cargo never deletes old builds, so `target/` keeps growing: on 2026-11-11 it had reached 10 GB, against 1 GB for a fresh build. When it gets big, `cargo clean`; a full rebuild of the tests takes about 40 seconds on the MacBook Air. Debug builds keep file and line numbers only (`[profile.dev]` in `Cargo.toml`), which makes them about a sixth smaller and no slower.

The nodes run Linux x86-64. The Mac builds one static file of about 1.5 MB with zig; the tools are installed once:

```bash
brew install zig
cargo install cargo-zigbuild
rustup target add x86_64-unknown-linux-musl
```

```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl -p bf-agent
```

## The agent
`bf-agent` runs the service. Every 30 seconds it makes WireGuard match the list, then forgets any device with no handshake for 5 minutes (removes it and adds it back), so a server never keeps a disconnected device's IP address (decision 020). `bf-agent probe` signs a status request to the local service with the node's own secret and prints the answer (exit 0 on success), so the secret never leaves the node. `bf-agent trackers build <list> <allow file> <zone file>` turns a downloaded EasyPrivacy into the resolver's zone (see "Tracker blocking" below); it needs no secret and no network.

| Setting | Default |
|---|---|
| `BF_LISTEN` | `127.0.0.1:9870` (must be localhost) |
| `BF_INTERFACE` | `wg0` |
| `BF_SECRET_FILE` | `/etc/barely-free/agent.secret` (hex, at least 32 bytes) |
| `BF_STATE_DIR` | `/var/lib/barely-free` |
| `BF_ONLINE_SECS` | `180` (must be under 300, the time after which an idle device is forgotten) |
| `BF_WG_BIN` | `wg` |
| `BF_TRACKERS` | unset (off); `nft` keeps the set `inet barely_free_dns off_<interface>` of devices whose tracker blocking is off |
| `BF_NFT_BIN` | `nft` |

The requests (`GET /v1/status`, `PUT /v1/peers`), their signing and every answer are in [specs/agent.md](specs/agent.md).

## Deploy to a node
```bash
deploy/deploy-agent.sh root@<node ip> -i ~/.ssh/<key> -o IdentitiesOnly=yes
```

It builds on the Mac, copies the binary and the systemd unit, creates `/etc/barely-free/agent.secret` on the node the first time (the secret is made there and never leaves it), starts the service and runs `bf-agent probe`. Safe to run again to update. The service runs as a throwaway user with only `CAP_NET_ADMIN` and no network except localhost.

To check a build against a real WireGuard before or after a change to how the agent talks to `wg`, run `deploy/node-selftest.sh` on a node (the commands are in its header). It works on two throwaway interfaces and never touches `wg0`.

### HTTPS in front of the agent
The agent only listens on localhost. Caddy on each node puts HTTPS in front of it on port 8443, as `<node>.agent.internal`, with a certificate from Caddy's own CA (no DNS record needed; the caller connects to the node's IP, sends that name and trusts only that node's root from `deploy/node-roots/`). The holding page on ports 80 and 443 is not touched.

```bash
deploy/deploy-caddy.sh root@<node ip> <node> -i ~/.ssh/<key> -o IdentitiesOnly=yes      # toronto or dallas
ssh -i ~/.ssh/<key> -o IdentitiesOnly=yes root@<node ip> 'sh -s -- <node> <node ip>' < deploy/node-tlscheck.sh
```

Set `BF_CONTROL_IP=<address>` to open port 8443 to one address instead of everyone; `BF_UNDO=1` takes it back out. **Since 2026-11-12 both servers allow 8443 only from the web VM (`<vm ip>`)**: always run `deploy-caddy.sh` with `BF_CONTROL_IP=<vm ip>`, or it opens the port to everyone again. If the VM's home address changes, the server-down alerts fire; run it with the new address and delete the old rule (`ufw status numbered`). Details and the reasons: [decision 006](docs/decisions/006-agent-tls-with-caddys-own-ca.md) and [the agent module](docs/modules/bf-agent.md).

## The website
`bf-control` serves the front page for barely-free.com on `127.0.0.1:18500` (`BC_LISTEN`, localhost only). Every response carries a strict content security policy; nothing loads from outside and no scripts run. A "Costs and funding" section has one plain link to the project's Ko-fi page for donations. The look is deliberately plain (system fonts, hairline rules, one green; redesigned 2026-11-10, deployed in 0.3.0). It runs on the web VM and reaches the world through a Cloudflare tunnel.

```bash
deploy/deploy-web.sh root@<vm ip> -o Port=<ssh port>          # build, copy the database aside, install and start it on the VM
ssh -p <ssh port> root@<vm ip> 'sh -s' < deploy/route-barely-free-com.sh   # send barely-free.com to it in haproxy (reversible)
```

Before the new program is put in place, `deploy-web.sh` stops the service and copies the database to `/var/lib/barely-free/control.db.before-deploy-<UTC time>` with the new program's own `backup` (owner `barely-free`, mode 0600, without the short-lived sign-in records; the newest five copies are kept), because a newer program may upgrade the schema and an older one cannot read an upgraded database. To go back: stop the service, put the old binary and that copy back, start it.

What is left before it is public, and how the tunnel is wired: `docs/modules/bf-control.md`.

### Legal, help and security pages (built, not deployed)
Six pages, in the same plain style and with no scripts:
- `/terms`, the terms of use;
- `/privacy`, the privacy policy;
- `/abuse`, reporting abuse and copyright notices;
- `/transparency`, the legal requests received;
- `/help`, help and support;
- `/security`, reporting a security problem.

Next to them is `/.well-known/security.txt`. Every public page now has one menu (How it works, Servers, Help, Account) and one footer (Service, Help and Legal links, "© 2026 Laoel Beqiri · Ontario, Canada", the theme buttons). The sign-in page says that continuing means agreeing to the terms and the privacy policy.

There is no email address (Lao, 2026-11-12). Every "contact us" leads to `/help#contact`, which says the planned community server will be the way to reach us; put its link there when it exists. Abuse complaints reach the hosting company first (the servers' addresses are theirs), so watch the hosting account's inbox.

**Before deploying:**
- Confirm the zeros on the transparency page.
- Read vpshostingservice.co's own terms.

**Every year:** move `Expires` in `crates/bf-control/web/security.txt` on before it passes (2027-11-01 now), together with the security page's date; a test holds the two less than a year apart.

The privacy policy's numbers are tied to the code by tests: change a lifetime or limit and the test names the sentence to fix. Details: `docs/modules/bf-control.md` ("Legal, help and security pages"), `specs/legal-and-support.md`, decision `docs/decisions/018-legal-and-support-pages.md`.

### Search engines (deployed 2026-11-12)
So that Google and Bing can find the public pages and name them properly (Lao, 2026-11-12). Nothing about it is visible on the site, nothing runs in the browser and no tracking is added.
- `/sitemap.xml` lists the eight public pages (`/`, `/help`, `/terms`, `/privacy`, `/abuse`, `/transparency`, `/security`, `/cookies`) by their `https://barely-free.com/...` addresses. It has no `lastmod`, `priority` or `changefreq`: Google ignores the last two and trusts `lastmod` only when it is provably true.
- `/robots.txt` allows everything and names the sitemap. It has **no `Disallow` line and never mentions `/admin`**: a `Disallow` hides a page's `noindex` from Google, and a line for `/admin` would announce a page the site hides.
- Every public page names itself as its canonical address (`<link rel="canonical">`, on the bare `barely-free.com`). `www.barely-free.com` answers with the same page, and this is what tells a search engine which one counts.
- `/check` is `noindex` and not in the sitemap (its page shows the visitor's own address). The sign-in side and the admin panel were already `noindex` or hidden.
- Each public page carries plain link-preview tags (Open Graph and `twitter:card` = `summary`) that repeat its own title, description and address, so a shared link shows its title and description in a chat app. There is no preview image yet. When sign-up is open the front page's preview description changes together with its description.
- The front page also carries one block of `WebSite` data (`name` "Barely-free", `alternateName` `barely-free.com`) so Google can name the site. It is data, not a script: it was checked in a real browser that the page's strict policy lets it be, and the "no scripts" tests still refuse any script that runs.

Tests (`src/web/tests/seo.rs`) tie the sitemap, `robots.txt`, the canonical links, the previews, the data block and the files in `web/` together: a new page file must be added to the sitemap or named as kept out. Details: `docs/modules/bf-control.md` ("Search engines"), `specs/seo.md`, decision `docs/decisions/021-search-engines.md`, `research/seo/RESEARCH.md`.

**After deploying (your own accounts, not the program's):**
1. Add `barely-free.com` to Google Search Console as a *Domain* property, verified by a DNS TXT record in the Cloudflare account that holds the name, then submit `https://barely-free.com/sitemap.xml` in its Sitemaps report. Do the same in Bing Webmaster Tools (it can import the Google verification).
2. Optional: a Cloudflare redirect rule from `www.barely-free.com/*` to `https://barely-free.com/$1` (301). The canonical links already settle the duplicate; the redirect is the stronger signal.
3. Cloudflare keeps `robots.txt` and the sitemap at its edge, so a change can show a few hours late (after the first deploy the edge served the old `robots.txt` for hours; purge `/robots.txt` in the Cloudflare dashboard to refresh it sooner).

## The admin tool
`bf-control` with no arguments serves the website. With arguments it is the admin tool, working on a SQLite database (`BC_DB`, default `/var/lib/barely-free/control.db`). Sign-up is closed unless `BC_OPEN_SIGNUP=1` is set (see "Open sign-up" below): accounts are made here.

```bash
export BC_DB=./control.db                  # anywhere you can write, to try it out
bf-control account add lao                 # prints the account id
bf-control device add 1 phone              # prints address, public key and, once, the private key
bf-control account list
bf-control device list
bf-control kick 1 30m --by lao --reason "testing"   # 90s, 30m, 2h, 7d or forever; the length is required
bf-control kick list                      # every kick, including those of removed devices
bf-control lift 1 --by lao
bf-control device remove 1                 # kept as history; a kick still in force stays in force
bf-control peers                           # the peer list the nodes will get, as JSON
```

Exit codes: 0 done, 1 refused (the reason is printed), 2 not understood (the usage is printed). The database file is created readable by its owner only, and a command that makes a new one says so on stderr (so a mistyped `BC_DB` shows). Devices get the lowest free address from `10.77.0.2`; an account holds at most 3 devices. While any device of an account has a kick in force (a removed one's too), the account cannot add a device, here or on the account page, and its owner cannot remove the kicked one. Lift the kick, or let it run out, to free the account. A kick still takes only that one device off the servers, so to cut someone off, kick each of their devices (decision `docs/decisions/012-a-kick-blocks-adding-devices.md`). The private key is shown once and never stored. The rules, the tables and the reasoning: `specs/control-core.md`, `docs/SCHEMA.md`, `docs/modules/bf-control.md`. The same program is on the web VM as `/usr/local/bin/bf-control`; run it there as the `barely-free` user (`runuser -u barely-free -- /usr/local/bin/bf-control ...`).

## The node poller (deployed)
`bf-control` asks every node for its status every `BC_POLL_SECS` seconds (default 10, 2 to 300) over the pinned HTTPS of decision 006, and sends the peer list to any node that does not hold the current version, so a device made or kicked in the database reaches the nodes within a pass. It starts only if the database already exists, and a node it cannot reach never stops the website. The front page's Servers section and `/status` show each registered server as **Up**, **Overloaded**, **Being fixed**, **Down** or **Status unknown** (never a count of 0; see "Server status page" below).

```bash
# once per node, run by you: the secret goes node -> VM through your own ssh and is never shown
deploy/set-node-secret.sh toronto "root@<node ip> -i ~/.ssh/<key> -o IdentitiesOnly=yes" "root@<vm ip> -o Port=<ssh port>"
deploy/deploy-web.sh root@<vm ip> -o Port=<ssh port>      # also installs deploy/node-roots/*.pem

# on the VM
bf-control node add toronto <node ip>:8443 Toronto Canada --protocol amneziawg   # wireguard or amneziawg: what that agent's interface speaks
bf-control node set-protocol toronto amneziawg   # for a node registered before protocols (schema 5)
bf-control node check toronto      # one signed status request, the way the poller makes it
bf-control node list               # names, addresses, and whether each node's two files are usable
bf-control node disable toronto    # the site then says "Being fixed"; enable brings it back; remove retires it
bf-control list raise 9            # only if a node holds a newer list than a restored database
```

If a node's address is on the web VM's own outbound block list (`happ_fleet` in its `/etc/nftables.conf`, which resets every TCP port but 22 to the old VPN fleet; Dallas is on it), its card reads "Not responding" with "cannot connect"; `deploy/vm-allow-node.sh <node ip> root@<vm ip> -o Port=<ssh port>` adds one accept rule for that node's port 8443 (you run it; it changes the VM's firewall).

Settings: `BC_NODES_DIR` (default `/etc/barely-free/nodes`, holding `<name>.secret` and `<name>.pem`), `BC_POLL_SECS`, `BC_DB`. Details: `docs/modules/bf-control.md`, `specs/poller.md`, `docs/decisions/008-poller-design.md`.

## Adding a device (deployed; needs the nodes prepared)
Signed in, the account page (`/account`) lists your devices and lets you add one: it makes a WireGuard key, shows the setup as a QR code, a downloadable `.conf` and plain text, and keeps only the public key. The private key is shown once. Up to 3 devices per account. It needs a node that is up, which needs the node's secret on the VM and its network prepared:

```bash
deploy/node-network.sh root@<node ip> -i ~/.ssh/<key> -o IdentitiesOnly=yes     # once per node: 10.77.0.1/16 and NAT
deploy/node-isolate-clients.sh root@<node ip> -i ~/.ssh/<key> -o IdentitiesOnly=yes   # once per node: devices cannot reach each other
deploy/set-node-secret.sh <name> "root@<node ip> -i ~/.ssh/<key> -o IdentitiesOnly=yes" "root@<vm ip> -o Port=<ssh port>"
```

Details: `docs/modules/bf-control.md` ("Add a device on the account page").

## Both protocols on every server (built, not deployed)
Every server offers WireGuard and AmneziaWG. When adding a device you pick the server ("Closest to you" is the default, see below) and the app: WireGuard (the default whenever a server can take it) or AmneziaWG (for networks that block VPNs). The account page and the device page link to the official apps for iPhone/iPad, Mac, Android, Windows and Linux (AmneziaWG has no Linux app). AmneziaWG devices are on `10.77.0.0/16` (as today), WireGuard devices on `10.78.0.0/16`, and one device's two addresses share their last two numbers. Each server runs one agent per interface; the second is `bf-agent-<protocol>.service` on `127.0.0.1:9871`, reached as `<name>.agent.internal:8443`. Details: `specs/dual-protocol.md`, decision `docs/decisions/013-both-protocols-on-every-server.md`, `docs/modules/bf-control.md` ("Both protocols on every server").

To switch it on, **you** run these in this order (each script is safe to run again):

```bash
# 1. The website. It copies the database aside, then upgrades it to schema 6 (an older build cannot read it afterwards).
deploy/deploy-web.sh root@web.<your-tailnet>.ts.net
#    then on the VM, at once: until Toronto's agent has a protocol, no device can be added.
bf-control node set-protocol toronto amneziawg

# 2. Dallas: move its WireGuard to 10.78 (live, nobody is disconnected), then tell the website.
deploy/node-wireguard-range.sh root@dallas.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes
bf-control node set-protocol dallas wireguard          # on the VM

# 3. Dallas: AmneziaWG. If it says UDP 443 is held, run deploy/deploy-caddy.sh root@dallas.<your-tailnet>.ts.net dallas ... first (it turns Caddy's HTTP/3 off).
deploy/node-add-protocol.sh root@dallas.<your-tailnet>.ts.net amneziawg dallas-awg -i ~/.ssh/your_key -o IdentitiesOnly=yes

# 4. Toronto: WireGuard.
deploy/node-add-protocol.sh root@toronto.<your-tailnet>.ts.net wireguard toronto-wg -i ~/.ssh/your_key -o IdentitiesOnly=yes

# 4b. Both servers: the backup ports (WireGuard also on UDP 53 and 123, AmneziaWG also on 4500) for the
#     interfaces made before node-add-protocol.sh had them built in (Toronto's awg0, Dallas's wg0).
deploy/node-extra-ports.sh root@dallas.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes
deploy/node-extra-ports.sh root@toronto.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes

# 5. Check, on each server: one key handshakes on both protocols (prints PASS or FAIL).
ssh -i ~/.ssh/your_key -o IdentitiesOnly=yes root@dallas.<your-tailnet>.ts.net 'sh -s' < deploy/node-dual-selftest.sh
ssh -i ~/.ssh/your_key -o IdentitiesOnly=yes root@toronto.<your-tailnet>.ts.net 'sh -s' < deploy/node-dual-selftest.sh

# 6. The two new agents' secrets go node -> VM through your own ssh. Without the fourth argument the script
#    refuses a name that has its own secret file on the server.
deploy/set-node-secret.sh dallas-awg "root@dallas.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes" "root@web.<your-tailnet>.ts.net" /etc/barely-free/agent-dallas-awg.secret
deploy/set-node-secret.sh toronto-wg "root@toronto.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes" "root@web.<your-tailnet>.ts.net" /etc/barely-free/agent-toronto-wg.secret

# 7. On the VM: register them, with exactly the title and place of the server's first agent (node list shows them),
#    so each server stays one card and one choice.
bf-control node add dallas-awg <dallas ip>:8443 Dallas "United States" --protocol amneziawg
bf-control node add toronto-wg <toronto ip>:8443 Toronto Canada --protocol wireguard
bf-control node check dallas-awg
bf-control node check toronto-wg
#    and where each server is, on all four agents, for "Closest to you":
bf-control node set-location toronto 43.65,-79.38
bf-control node set-location toronto-wg 43.65,-79.38
bf-control node set-location dallas 32.78,-96.80
bf-control node set-location dallas-awg 32.78,-96.80
```

`deploy/deploy-agent.sh` now keeps the interface each server's first agent drives (Toronto: `awg0`) and restarts the second agent too, so redeploying the agent later is the same command as before.

**Backup ports.** Files use UDP 51820 (WireGuard) and 443 (AmneziaWG). If a network blocks those, a person edits the tunnel and changes the number at the end of `Endpoint` to 53 or 123 (WireGuard) or 4500 (AmneziaWG); the account and device pages say so. DNS is optional: per-server `A` records with Cloudflare's proxy **off** (Cloudflare does not carry UDP), `toronto.barely-free.com` → `<toronto ip>` and `dallas.barely-free.com` → `<dallas ip>`.

## Closest to you (built, not deployed)
"Closest to you" is the first choice on the add form, and checked. The server is picked once, when the device is made: the nearest one that is not busy, from roughly where the person is (Cloudflare's `cf-iplatitude`/`cf-iplongitude` headers, used for that one choice and never stored or logged) and where each server is (`bf-control node set-location`, schema 6). A server is busy when its devices online (both agents together) reach `BC_NODE_BUSY_ONLINE` (default 40) or its one-minute load reaches `BC_NODE_BUSY_LOAD` (default 0.9). Servers within 300 km of each other count as equally near and the less loaded wins; with no location the least loaded wins. Someone already on the VPN is located at the server they are on.

The location headers exist only after the owner of the barely-free.com Cloudflare zone switches on the Managed Transform **"Add visitor location headers"** (one switch, on every plan; `research/trackers-and-closest/RESEARCH.md` on `feat/trackers` links the Cloudflare docs). Until then every device goes to the least loaded server. Details: decision `docs/decisions/014-closest-server.md`, `docs/modules/bf-control.md` ("Closest to you").

## Tracker blocking (built, not deployed)
Every server answers DNS on its in-tunnel addresses, `10.77.0.1` (AmneziaWG) and `10.78.0.1` (WireGuard), with unbound. Port 53 blocks known trackers (EasyPrivacy, only its plain domain rules, refreshed daily; no ad list); port 5300 does not. New device files name their server's address as their only DNS. On the account page each device has an Allow trackers / Block trackers button: a device with blocking off is sent from 53 to 5300 by an nftables rule whose set the server's agents keep in step, within seconds and with nothing to download again. Nothing about lookups is logged; unbound forwards to Quad9's threat-blocking resolver (`9.9.9.9`, `149.112.112.112`) over TLS, so names known to spread malware are refused on both ports, whatever a device's tracker switch says (decision 022). Deploying a change means running `deploy/node-resolver.sh` on each server again. Details: `specs/trackers.md`, decision `docs/decisions/015-tracker-blocking-on-the-servers.md`, `docs/modules/bf-agent.md` and `docs/modules/bf-control.md` ("Tracker blocking").

To switch it on, **you** run these, after "Both protocols on every server" above (each is safe to run again):

```bash
# 1. The new agent on each server. It builds on this Mac, keeps the interface each server's
#    first agent drives (Toronto: awg0) and restarts both agents of that server on the new build.
deploy/deploy-agent.sh root@dallas.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes
deploy/deploy-agent.sh root@toronto.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes

# 2. The resolver, the redirect and the daily list on each server. It ends by asking each address
#    whether it resolves, blocks a listed tracker on 53 and not on 5300, and exits 1 if not.
deploy/node-resolver.sh root@dallas.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes
deploy/node-resolver.sh root@toronto.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes

# 3. Only then the website, so no device file names a resolver that is not there yet.
deploy/deploy-web.sh root@web.<your-tailnet>.ts.net
```

Devices made before step 3 keep `DNS = 1.1.1.1` and are not filtered until they are removed and added again. Run `deploy/node-resolver.sh` again after adding an agent to a server, so the new agent gets the switch. A switch on the account page reaches the servers on the poller's next pass (10 s). Names that must never be blocked go in `/etc/barely-free/trackers-allow.txt` on each server (`systemctl start bf-trackers-update.service` applies them at once).

## Backups (built, not deployed)
Every night the web VM copies the accounts database (`bf-control backup`: one consistent snapshot, nothing deleted left in it). It packs the copy with the fingerprint key (`control.key`) and encrypts it with [age](https://github.com/FiloSottile/age) to **your** public key, so the VM can lock a backup but never open one. It then sends it to both servers, which keep the newest 30. The VM's key on the servers can only add a new file, nothing else. The admin overview shows the last backup and warns when one failed, missed a server or is more than 36 hours old. Details: `specs/backup.md`, decision `docs/decisions/016-nightly-encrypted-backup.md`, `docs/modules/bf-control.md` ("Backups").

To switch it on, **you** run these (each is safe to run again):

```bash
# 0. Once, on this Mac: your age key pair. Keep key.txt in a password manager and on paper,
#    never on a server: without it nobody, you included, can open a backup.
brew install age
age-keygen -o key.txt            # prints "Public key: age1..."

# 1. The VM: age, the script, the timer (not started yet), the VM's own backup key and your
#    public key. Saves the VM's backup public key to target/backup/vm-backup-key.pub.
deploy/setup-backup.sh root@web.<your-tailnet>.ts.net age1<your public key>

# 2. Each server: the bf-backup user, the receiver and the VM's key pinned to it. Adds the
#    server's host key to target/backup/known_hosts.
deploy/node-backup-receiver.sh root@toronto.<your-tailnet>.ts.net target/backup/vm-backup-key.pub -i ~/.ssh/your_key -o IdentitiesOnly=yes
deploy/node-backup-receiver.sh root@dallas.<your-tailnet>.ts.net target/backup/vm-backup-key.pub -i ~/.ssh/your_key -o IdentitiesOnly=yes

# 3. The VM again: pins the servers, runs one backup now and prints how it went, starts the timer.
deploy/setup-backup.sh root@web.<your-tailnet>.ts.net --finish target/backup/known_hosts

# 4. The drill, once after setup and now and then: fetch and check the newest backup. It changes
#    nothing on any server. Delete the folder afterwards: it holds the database in the clear.
deploy/restore-backup.sh fetch root@toronto.<your-tailnet>.ts.net key.txt -i ~/.ssh/your_key -o IdentitiesOnly=yes
```

To restore for real, after a `fetch`: `deploy/restore-backup.sh put root@web.<your-tailnet>.ts.net target/restore/control-<time>`. It keeps the old database aside, restores, restarts the website and shows each server's list version. Run the `bf-control list raise <n>` it names for a server that is AHEAD. Everything since that backup is lost.
## Am I on the VPN? (built, not deployed)
`https://barely-free.com/check` tells a device whether it is on Barely-free and through which server. It compares the address Cloudflare saw with the servers' addresses, and keeps nothing. The front page's questions and the account page link to it. Details: `docs/modules/bf-control.md` ("`/check`").

## Server status page (built, not deployed)
`https://barely-free.com/status` shows every server as one word, and the front page's Servers cards use the same words:

| Word | When |
|---|---|
| **Up** | some agent of the server is online and it is not busy |
| **Overloaded** | online, and its devices online (both agents together) reach `BC_NODE_BUSY_ONLINE` (default 40) or its load reaches `BC_NODE_BUSY_LOAD` (default 0.9): the same rule that makes "Closest to you" skip it |
| **Being fixed** | the server is disabled: `bf-control node disable <name>` (and `enable` when it is back) |
| **Down** | every agent has failed 3 passes in a row (about 30 s); you are emailed after 3 minutes |
| **Status unknown** | no recent reading (the poller stopped, or an agent has not answered yet); it does not mean down |

If one of a server's two agents (WireGuard or AmneziaWG) is down or disabled and the other works, the server keeps its word and a line under it names the app. For a full repair, disable both agents (`node disable dallas`, `node disable dallas-awg`). To retire a server, use `node remove`, not `node disable`, or the site will keep saying it is being fixed.

The page gives the word for each server, and for a working one its **load**: how close it is to being overloaded, in percent, rounded down to the nearest 10 (100% means Overloaded, so a server one device under the line shows 90%). It is worked out from the same two numbers as the Overloaded rule (devices online over `BC_NODE_BUSY_ONLINE`, load over `BC_NODE_BUSY_LOAD`, whichever is higher). There are no exact device counts, no raw load figures and no node names, and the front page's cards stay words only. It is not cached, not in the sitemap, and marked `noindex`. Decision `docs/decisions/025-server-status-page.md`, spec `specs/status-page.md`, details in `docs/modules/bf-control.md` ("Server status page"). No setting or database change; deploy with `deploy/deploy-web.sh`.

## When each device last connected (built, not deployed)
The account page shows, for each device, whether it is connected now and through which server and app, or when it last was ("Last connected through Dallas (AmneziaWG), 3 hours ago"). It comes from the servers' own handshake times, which the poller reads every 10 seconds and keeps only in memory. Details: `docs/modules/bf-control.md`.

## ClashMi, the recommended setup
When anyone adds a device, the page first offers a profile for the ClashMi app. It holds the device on both servers, both apps and every backup port, and ClashMi moves to the next one by itself when a connection stops answering. The official WireGuard or AmneziaWG app (file, QR code, text) is one tap below it. Decision `docs/decisions/019-clashmi-is-the-recommended-setup.md`. Details: `research/clashmi/RESEARCH.md`, `docs/modules/bf-control.md`.

## Alerts when a server stops answering (deployed, on)
When a server has not answered for 3 minutes, the website's program emails you once, and again when it is back. Both servers dropping together is one email, and there are at most 10 a day. It sends through the same Resend key as the sign-in codes. To switch it on, **you** put your address on the VM (owner-only, like the other private files), then restart the website:

```bash
ssh root@web.<your-tailnet>.ts.net 'read -r a && printf "%s\n" "$a" | install -m 0600 -o barely-free -g barely-free /dev/stdin /etc/barely-free/alert-to && systemctl restart bf-control'
```

Type the address and press Enter. The log then says "alerts are on". Details: `docs/modules/bf-control.md` ("Alerts").

## Alerts when someone logs in from somewhere new (deployed, on)
When an SSH login to any of the three servers uses a key (or a password) from a network that key has not logged in from before, the website emails you once: "New login to Dallas: root from 203.0.113.7 at 2026-11-12 03:40 UTC, with the key lao-mac (SHA256:…)". It shares the down alerts' address, their Resend key and their 10 emails a day. A network is the address's `/24` (IPv6: `/48`), so your usual places stay quiet. On every server, `bf-logins.timer` (installed by `deploy-web.sh` and `deploy-agent.sh`) writes the recent logins once a minute for the group `bf-logins`; the VPN servers' agents report them in their signed status, and the website reads the VM's own. The pairs it knows are in `/var/lib/barely-free/known-logins`. Decision `docs/decisions/023-login-alerts.md`.

To switch it on, in this order (website first, so it never sees a field it does not know):

```bash
deploy/deploy-web.sh root@web.<your-tailnet>.ts.net
```

```bash
deploy/seed-known-logins.sh
```

```bash
deploy/deploy-agent.sh root@dallas.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes
```

```bash
deploy/deploy-agent.sh root@toronto.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes
```

The seed script teaches the website the last 90 days of logins on all three servers (nothing is stored on the Mac) and restarts it. The website's log says "login alerts are on". To test it, log in to a server from a new network, such as a phone's hotspot: one email should arrive within a minute. `BF_LOGINS=off` in an agent's environment stops it reporting logins.

## SSH only through Tailscale (done 2026-11-12: public SSH closed)
The servers accept SSH only from the admin's tailnet, still with SSH keys (decision `docs/decisions/024-ssh-through-tailscale.md`). **Every SSH command in this README uses the Tailscale names:** `root@dallas.<your-tailnet>.ts.net`, `root@toronto.<your-tailnet>.ts.net` (both with `-i ~/.ssh/your_key -o IdentitiesOnly=yes`) and `root@web.<your-tailnet>.ts.net` (the VM, port 22). Tailscale must be on on the Mac. If Tailscale fails on a server, the way back in is the hosting panel's console (safe mode or emergency mode) for Dallas and Toronto, and the host PC for the VM. Public SSH is closed by two layers:
- on all three, an sshd `Match Address` block (`/etc/ssh/sshd_config.d/zz-tailnet-only.conf`) refuses every user from outside `100.64.0.0/10` and `fd7a:115c:a1e0::/48`;
- on Dallas and Toronto, ufw's public `22/tcp` rule is deleted, so port 22 does not answer at all.

The VM's port 2222 (the host PC's port forward) still answers but lets nobody in. How it was set up:

1. **You, in Tailscale's admin console:** turn on two-step login and sign out old sessions; paste `deploy/tailscale-policy.hujson` into Access controls; make one **one-off, pre-tagged** auth key per server (`tag:node` for Dallas and Toronto, `tag:web` for the VM). Also check you can log in to the hosting company's web console for Dallas and Toronto.
2. **You, one server at a time** (it asks for the key with a hidden prompt; never paste a key into a chat):

```bash
deploy/tailscale-join.sh dallas root@dallas.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes
```

```bash
deploy/tailscale-join.sh toronto root@toronto.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes
```

```bash
deploy/tailscale-join.sh web root@web.<your-tailnet>.ts.net
```

Done on 2026-11-12 for all three (`dallas`, `toronto`, `web`); SSH by those names over Tailscale works, for example `ssh root@dallas.<your-tailnet>.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes`. The nightly backups go to the nodes' Tailscale addresses since 2026-11-12 (`/etc/barely-free/backup-targets`); one run by hand went to both. VPN users' traffic to the tailnet is dropped on both VPN servers by `deploy/node-tailnet-guard.sh root@<node ip> -i ~/.ssh/your_key -o IdentitiesOnly=yes` (done 2026-11-12; safe to run again). It installs Tailscale from its stable repository for Debian 13 (signed by `deploy/tailscale-archive-keyring.gpg`, checked into this repo), joins as that name with Tailscale SSH off and the server's DNS left alone, and prints the server's Tailscale address. Then SSH to each server by its Tailscale name is tested, the backups move to the Tailscale addresses, and only then is public SSH closed (steps in the decision).

## Sign-in (built, off until configured)
`bf-control` can serve sign-in pages (`/signin`, then `/verify` for the six-digit code, `/signout`, `/account`) next to the website. They are **off unless fully set up**: without the control key file, the Resend key file and valid settings the website runs exactly as before and its log says why sign-in is off. The settings are `BC_KEY_FILE`, `BC_RESEND_KEY_FILE`, `BC_RESEND_URL`, `BC_MAIL_FROM`, `BC_ORIGINS` and `BC_DB`, with defaults and details in `docs/modules/bf-control.md` ("Sign-in pages"). Accounts that can sign in are made by an admin; an address is kept only as a fingerprint:

```bash
bf-control account add lao --email lao@example.com      # makes the key file on first use (mode 0600)
bf-control account set-email 1 new@example.com          # give or change an account's address
```

### Open sign-up (deployed, OPEN since 2026-11-12)
Set `BC_OPEN_SIGNUP=1` in the service's environment and anyone can make an account: they type any email address, receive the six-digit code, and typing it creates the account (label `member-<id>`, 3 devices) and signs them in. Unset or `0` keeps the closed beta; any other value keeps sign-in off and the log says why. Each UTC day at most **60** code requests for new addresses are taken (the rest of the 90 emails a day is kept for people who already have accounts) and at most **20** new accounts are made; past either, a new address sees "Sign-ups are full for today" and members are not affected. The front page and the sign-in pages say "closed beta" only while it is off. The terms page and the abuse contact it promised are built (see "Legal, help and security pages" above), not deployed yet. Details: `specs/open-signup.md`, decision `docs/decisions/010-open-sign-up.md`.

Lao opened sign-up on 2026-11-12: `deploy/bf-control.service` sets `BC_OPEN_SIGNUP=1` (pinned by `tests/service_unit.rs`).

## The admin panel (deployed, not switched on yet)
Signed in as an admin, `/admin` shows an overview (accounts, devices, kicks in force, each server's state) and pages to list and make accounts, list and remove devices, and kick and lift. Two locks: the account must be an admin (only the command line can make one), and the **admin password** is asked for on `/admin` and unlocks the pages for 30 minutes; five wrong tries lock it for 15 minutes. Anyone else, and every other address under `/admin`, gets exactly the site's ordinary 404, so the pages cannot be found. Kicks and lifts are recorded under your account label and reach the servers within seconds.

```bash
# on the VM, once: let account 1 use the admin pages
runuser -u barely-free -- /usr/local/bin/bf-control admin grant 1
# on your Mac: set its password (hidden prompt, asked twice, 12+ characters; it never touches a file or a command line)
deploy/set-admin-password.sh 1 root@<vm ip> -o Port=<ssh port>
```

Run the script again to change the password; that also ends every open unlock and clears a lock-out. `bf-control admin revoke <id>` takes the rights and the password away. Details, limits and how it was tested: `docs/modules/bf-control.md` ("Admin panel"), `specs/accounts-and-admin.md`.

## Deleting an account (built)
On the account page, "Delete my account" (type `delete`) removes the account, its sign-in address and its devices, which leave the servers within seconds. In the admin panel, each account's label opens its page: its devices, last connections and kicks. "Delete this account" there needs the label typed, and never works on your own account. The nightly encrypted backups still hold a deleted account for up to 30 days. Decision `docs/decisions/017-deleting-an-account.md`.

## Cookies: staying signed in and the theme (deployed)
The site can set three cookies, all listed on `/cookies`: the sign-in session, the short-lived "which address was a code asked for" cookie, and a theme choice. On the code page a **"Keep me signed in on this device"** box (unticked by default) makes a session that lasts 60 days from the last time a signed-in page was used, up to a year from sign-in; unticked, a session lasts 60 days from sign-in as before. Every page's footer has **System / Light / Dark** buttons that work without any script. A signed-in visitor sees "Your account" on the front page. Deploying it upgrades the database to **schema 4** (one new column; an older binary then refuses the database, so keep the backup if you might roll back). Nothing to configure. Details: `docs/modules/bf-control.md` ("Cookies so the site remembers"), `specs/cookies.md`, decision `docs/decisions/011-kept-sessions-and-the-theme-cookie.md`.

## Sending a test email
The sign-in email can be tried before sign-in exists. Run this yourself, on the Mac; it asks for a Resend key with a hidden prompt (use a key with "sending access" limited to `barely-free.com`, and delete it afterwards):

```bash
deploy/mail-test.sh you@example.com
```

It builds `bf-control`, writes the key to a private temporary file, sends one email with a sample code through Resend, and deletes the file. Details: `docs/modules/bf-control.md`, "Mail and secrets".

## Order of work
1. Node agent: **done**, deployed to both nodes.
2. Control program core: accounts, devices, kick, admin command line, then the node registry, poller and pushing the list (**deployed**). Sign-up stays closed.
3. Website, sign-in, account page and add-a-device (**deployed**); both protocols on every server with app links (**built, not deployed**); admin panel, cookies (keep me signed in, theme, `/cookies`) and the plainer design (**deployed in 0.3.0**; the admin panel still needs an admin account and its password).
4. Closest-unless-overloaded steering.
5. Tracker blocking (**built, not deployed**; branch `feat/trackers`, on top of `dev` with both protocols merged).
6. Restricted-network profile (AmneziaWG), after a trial.
7. Guard rails, open sign-up (**built behind a switch, off**; no Turnstile yet), then move off the old build.

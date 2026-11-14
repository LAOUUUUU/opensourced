# 025: A public status page: one word per server, "Being fixed" is a disabled server
**Date:** 2026-11-14
**Status:** Accepted (Lao asked for "a page that shows all the servers that are up, being fixed, overloaded or just down", and approved the brief `research/status-page/RESEARCH.md` with "Yes, build it")

## Context
The front page showed three words (Online, Not responding, Status unknown). "Overloaded" was worked out only when a device was added ("Closest to you", decision 014), and a server that was switched off for repair (`bf-control node disable`) vanished from the site, as if it had never existed.

## Decision
- **Five words, one function.** `status::servers` turns the board into one word per server: **Up**, **Overloaded**, **Being fixed**, **Down**, **Status unknown**. The front page's cards and `/status` both use it (and the same `status::card`), so they cannot disagree. The old front-page words "Online" and "Not responding" became "Up" and "Down".
- **Overloaded** is "busy" as "Closest to you" already means it: devices online (all of a server's agents added up) at or over `BC_NODE_BUSY_ONLINE`, or the highest load at or over `BC_NODE_BUSY_LOAD`. One helper (`Candidate::add_reading`, `Candidate::is_busy`) serves both, so a server that is skipped for new devices is the server the page calls overloaded.
- **Being fixed is a disabled node.** No new table or column. The poller reads every node, visits the enabled ones as before, and puts a view for each disabled one on the board with the new `Health::BeingFixed`, no reading and no problem. It is never called. `bf-control node disable` and `enable` are the switch.
- **Down means every agent is down.** A server with an agent that is `Unknown` and another that is `NotResponding` reads Status unknown, as `alerts.rs` already treats it. One agent down beside a working one leaves the server Up (or Overloaded), with a line under it naming the app ("AmneziaWG is not responding.").
- **Words, and for a working server a rounded load.** No exact device count, no raw load figure, no node name, no address. With few people, "2 devices online" says when one person is connected. The page reads `Board::snapshot_counts` (counts and load kept for the busy rule; no device, handshake, login or problem text). **Changed 2026-11-14** (Lao: "put like apertancege thing", then chose "Load per server"): `/status` also shows each working server's load, the larger of devices online over `BC_NODE_BUSY_ONLINE` and load over `BC_NODE_BUSY_LOAD`, in percent **rounded down to the nearest 10**. It is 100 only when the server is Overloaded, so the percentage and the word cannot disagree. Rounding down means one to three devices read 0% and each step is four devices at the default limit, so the page shows roughly how full a server is, not who is on it. The front page's cards stay words only.
- **A live page is not a search result.** `/status` is `no-store`, `noindex`, has no canonical or link preview, and stays out of the sitemap (`KEPT_OUT` in the SEO tests). The header and footer are the same as every page's; `/status` is a way back for the theme buttons.

## Rejected
- **A separate maintenance flag with a note ("back at 20:00")**: needs a schema change, a command and a form. Disable already means "out of service on purpose" and also stops the poller pushing lists to a server mid-repair. It can be added later if a note is wanted.
- **Exact device counts or an unrounded load figure on the page**: see above. (A rounded load percentage, as Proton shows, was added later at Lao's request.)
- **Uptime percentage over 30 days**: needs a table written to on every pass; still a separate step if wanted.
- **Uptime history ("30 days")**: needs a table written to on every pass; a separate step if wanted.
- **Putting the link in the footer, at first**: the footer is held equal on every page by a test, so it touches every file. Added anyway on 2026-11-14 at Lao's request: "Server status" under Service on all twelve page files, kept equal by that same test.

## Consequences
- A disabled server now shows on the front page, the admin overview ("Being fixed", count "unknown") and `/check`, where before it vanished. Retire a server with `node remove`, not `node disable`.
- Disabling one of a server's two agents leaves the server Up (the other agent works) with a line saying the disabled app is being fixed. Disable both for a full repair.
- When the poller stops, every view (a disabled one too) reads Status unknown after 60 s.
- Alerts are unchanged: a `BeingFixed` view is neither Online nor NotResponding, so a disabled server sends no "down" email, and one that was down, then disabled, then comes back still sends "back".

## Related
`crates/bf-control/src/status.rs`, `poller.rs` (`Health::BeingFixed`, `snapshot_counts`), `web.rs` (`/status`, `front_page`), `specs/status-page.md`, `research/status-page/RESEARCH.md`, decisions 008, 014, 021

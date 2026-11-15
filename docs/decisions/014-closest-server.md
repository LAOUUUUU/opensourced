# 014: "Closest to you": picked once, from Cloudflare's location headers, in memory only
**Date:** 2026-11-11
**Status:** Accepted (Lao approved the brief `research/trackers-and-closest/RESEARCH.md` on branch `feat/trackers`, and on 2026-11-10 asked for "auto selection not u select it"; the busy numbers are settings because no numbers were named)

## Context
Since decision 013 every server offers both apps, and the add form made the person pick a server. The front page has promised "New devices are sent to the nearest server, and to another one when it is overloaded". The website sits behind a Cloudflare Tunnel, so it only sees Cloudflare's view of the person.

## Decision
- **Chosen once, when the device is made.** The form's first Server option, checked by default, is "Closest to you" (`server=auto`). The file then points at that server for good; moving a device means removing it and adding it again, because the private key is never kept. Picking a server by name still works.
- **Where the person is: Cloudflare's `cf-iplatitude` and `cf-iplongitude`.** They are read in `post_add_device`, used for this one choice and dropped: never stored, never logged, never shown back. Each must be sent exactly once and be a plain decimal number in range; anything else (missing, repeated, `NaN`, `inf`, an exponent, out of range, not text) is "no location". They exist only once the barely-free.com zone owner switches on the Managed Transform "Add visitor location headers". Until then everyone is "no location".
- **Where each server is: `nodes.lat` and `nodes.lon` (schema 6)**, set by `bf-control node set-location <name> <lat>,<lon>` on each agent (Toronto `43.65,-79.38`, Dallas `32.78,-96.80`). A server takes the first location among its agents. One without a location ranks after every one with one.
- **The rule (`closest::pick`).** Only servers with an agent of the chosen app that is Online and has a reading are considered. A server is busy when the devices online on all its agents together reach `BC_NODE_BUSY_ONLINE` (default 40), or the highest one-minute load its agents report reaches `BC_NODE_BUSY_LOAD` (default 0.9). Amended 2026-11-15 (decision 030): the load is the lowest of the last five minutes of readings, so a short spike does not count. Busy servers are skipped. Of the rest, those within 300 km of the nearest count as equal, and the less loaded wins: fewer devices online, then lower load, then nearer, then first on the board. With no location all count as equally near, so the least loaded wins. If every server is busy, the one with the fewest devices online (furthest under the cap) is chosen.
- **Settings refuse nonsense.** `BC_NODE_BUSY_ONLINE` is a whole number from 1 to 100000 and `BC_NODE_BUSY_LOAD` a plain number above 0 and at most 1000; anything else keeps sign-in off with the reason in the log, like `BC_OPEN_SIGNUP`.

## Rejected
- **DNS "home" names steered through the Cloudflare API** (the original plan): it needs an API token in a zone Lao does not own, and only moves people when they reconnect.
- **A local GeoIP database**: a new dependency, a large monthly download and a credit link, for lower accuracy. **Country only**: New York is about four times closer to Toronto than to Dallas, but `US` would send it to Dallas.
- **Pinging the person from each server**: home routers and phones often do not answer, and it costs a round trip to both servers on every add.

## Consequences
- Someone who adds a device while already on the VPN is located at the server they are on. The front page says so under "What we keep".
- The headers are not authenticated: a person could send their own and pick a server, which they can already do by name. Nothing else depends on them.
- `devices` does not record which server a device uses (the brief's `devices.node_id`), so the account page cannot say it yet; that needs Lao's yes because it changes a table.
- A server titled exactly `auto` could not be chosen by name.

## Related
`crates/bf-control/src/closest.rs`, `docs/modules/bf-control.md` ("Closest to you"), decisions 008 and 013, `specs/dual-protocol.md`

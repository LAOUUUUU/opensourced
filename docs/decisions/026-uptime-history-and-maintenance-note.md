# 026: Uptime history and a maintenance note on the status page (schema 7)
**Date:** 2026-11-14
**Status:** Accepted (Lao: "do those like the pending", after the brief `research/status-history/RESEARCH.md`; the choices in it, 30 days, rounded down to 0.1%, maintenance not counted, 90 days kept, stood)

## Context
`/status` (decision 025) had no memory: the board is in RAM and resets on every deploy, so it could not say how reliable a server has been, and a server that was Being fixed said nothing about why or until when.

## Decision
- **One schema change, version 7, two independent parts.** `nodes.note` and the table `uptime_hours`. An older program refuses the file; the deploy copies the database first.
- **The note:** `bf-control node disable <name> --note "back at 20:00"` (1 to 100 characters, no control or text-reordering characters). `node enable` and a `disable` without a note clear it. It is shown under the cards as "Paris: back at 20:00", only while the server's word is Being fixed, escaped. Only an admin at the command line can set one.
- **The history:** hourly counts per server (title and place), `up` and `down`, written by the poller after each pass. A pass counts `up` when some agent is online (the word is Up or Overloaded) and `down` when the word is Down; **Being fixed and Status unknown count as nothing**, so planned maintenance is not held against a server (as Atlassian's Statuspage does) and a time nobody was looking says nothing either way.
- **The figure:** up over up-plus-down over the last 30 days (720 hours), as tenths of a percent **rounded down**, so a real outage never reads 100.0. It reads "99.8% over 12 days"; while the history is younger than 30 days it says how long it is, and a server with no counted pass says "no history yet". Never minutes or counts: this keeps the page's rule of showing no exact numbers about people (decision 025).
- **The path to the page:** the poller summarises the table after each pass onto the board (`Board::uptime()`), and `/status` reads the board. The web layer still never touches the database.
- **Retention:** rows older than 90 days are deleted once a day.

## Rejected
- A row per check (about 17,000 rows per server per day for the same percentage).
- Memory only: the board resets on every deploy.
- A third-party uptime service.
- Counting Being fixed as downtime.
- A separate maintenance table with start and end times: more than a one-line note needs.

## Consequences
- The history starts empty on deploy day and fills over 30 days.
- Gaps are not downtime: nothing is counted while the website is down or restarting, so its own outages are invisible in the figure, and an outage shorter than three failed passes (about 30 s) is not seen.
- A renamed server splits its history (the key is the title and place).
- The nightly backup holds the table (server health only, no personal data).
- The way back from schema 7 is the pre-deploy copy and the previous binary.

## Related
`crates/bf-control/src/uptime.rs`, `nodes.rs`, `status.rs`, `poller.rs`, `docs/SCHEMA.md`, `specs/status-history.md`, `research/status-history/RESEARCH.md`, decisions 008 and 025

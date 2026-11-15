# 030: A server is busy by load only if the load stayed high for five minutes
**Date:** 2026-11-15
**Status:** Accepted. Lao: "Yes, fix it", after the tuning of decision 029 showed a server marked Overloaded for a minute or two after each reboot and each module build.

## Context
"Overloaded" on the status page and the busy rule of "Closest to you" (decisions 014 and 025) used each agent's one-minute load average, read every 10 s, against `BC_NODE_BUSY_LOAD` (default 0.9). The servers have one vCPU, so any job that keeps it busy for a minute crosses that line: a reboot (Dallas read 1.39 forty seconds after boot), a DKMS module build, the nightly unattended-upgrades run (06:00–07:00 UTC), the tracker list update (00:00–01:00 UTC). Each time the public page said Overloaded and new devices were sent to the other server, although nothing was wrong.

## Decision
- The poller keeps each node's one-minute loads of the last five minutes (`poller::STEADY_LOAD_SECS` = 300) in memory and puts the **lowest** of them in the reading as `load_steady`. The busy rule, the status card's word and its load percentage all use `load_steady` (`status::together`, `App::closest_server`), so one helper still serves both and a server the page calls Overloaded is still the one "Closest to you" skips.
- So a server counts as busy by load only if every reading of the last five minutes was at or over the line. A real overload (people using the server) lasts far longer than that and still shows, five minutes later than before. As soon as the load drops, the steady load drops with it.
- `load1`, the load now, stays in the reading for the admin pages and the command line.
- A pass that fails keeps what was seen; readings older than five minutes are dropped on the next good pass. The history lives only in the website's memory: after a restart of the website the steady load starts again from the first reading.
- The device-count half of the rule (`BC_NODE_BUSY_ONLINE`) is unchanged: it does not spike.
- Nothing changed on the servers or in what the agents send.

## Consequences
- No more Overloaded after a reboot, a module build or a nightly job, unless the load stays high for five minutes.
- A server that becomes really busy is skipped for new devices five minutes later than before.
- For five minutes after the website restarts, a spike that started just before can still read as busy (the history is short); it clears as readings come in.

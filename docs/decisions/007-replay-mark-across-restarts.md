# 007: A restarted agent refuses requests signed at or before the highest time it had accepted
**Status:** Accepted — 2026-11-10 (Lao said yes; it changes the signature check)

## Context
Decision 002 stops replays with a nonce cache in memory plus a 60-second window. A restart empties the cache, so for up to 60 seconds a copy of a request accepted just before could be accepted again. A replayed `PUT /v1/peers` is neutralized by its version, so the practical risk was a replayed `GET /v1/status` (masked, but still activity data). Over plain HTTP anyone on the path could have captured one; with TLS (decision 006) only someone who can break TLS could. It was still a hole, and Lao asked for it to be closed.

## Decision
- The agent keeps the **highest request time it has accepted** on disk, as the replay mark: `replay-mark` in the state directory, one decimal number, mode 0600, written through a temporary file and a rename.
- It is written **before** the request is acted on, only by requests that passed every check (shape, signature, window, floor, nonce), and only when the number goes up.
- After a restart the verifier gets that mark as its **floor** and refuses every request signed **at or before** it (`Refusal::BeforeRestart`; the caller still answers the same empty 404). A request accepted before the restart has a time at or below the mark, so every copy of it is refused, whatever the clock says.
- No mark file (the first start of a build that has this): the floor is the agent's start time. The mark file cannot be read (damaged, not a number): the floor is the start time plus 60 seconds, a quiet minute, because a zero would switch the protection off. Both are logged.
- If the mark cannot be written (disk full), the failure is logged and the request is still served: the agent stays up, and only a restart before the next good write reopens the gap.
- The mark is not synced to disk, because it sits on the path of every accepted request. A restart or a crash of the agent keeps it; only a power cut that loses the file's last write could reopen the gap, for under a minute.

## Consequences
- The gap is closed for restarts and deploys, independent of clock skew between the control program and the node, because the mark is in the caller's own timeline.
- The price: right after a restart a *legitimate* request signed at or before the mark is refused too (for example one that was in flight, or signed in the same second as the last accepted one). The control program retries on its next pass, so it is a delay of seconds. The first poll of a new process must therefore be signed at a later second than the last one of the old process, which the 30-second poll interval gives.
- The first start with no mark file refuses requests signed in the start second. `deploy/deploy-agent.sh` therefore retries its probe for up to 10 seconds (the first Dallas deploy showed it: the probe was signed in the second the agent started and got a 404).
- A clock that jumped backwards on both ends (so a mark is far ahead of the real time) would make the agent refuse the control program until the time catches up, or until `replay-mark` in the state directory is deleted. The start-up log line names the floor. This was judged better than capping the floor and reopening the gap in that case.
- The nonce cache stays, for requests within one process.
- `deploy/node-selftest.sh` now sends one captured request again after a restart; with the old build it got 200, with this one 404.

## Alternatives rejected
- **A quiet minute after every start:** simple and skew-proof only if the minute is long enough, but it refuses every legitimate request for that minute and breaks the deploy probe.
- **Rejecting requests older than the agent's start time:** wrong whenever the control program's clock is ahead of the node's: copies signed in the last seconds before the restart stay replayable.
- **Writing every nonce to disk:** exact, but a file that grows with every request and needs compaction, where one number does the same job.

## Related
- [002 Signed requests](002-signed-requests.md), [006 Agent TLS](006-agent-tls-with-caddys-own-ca.md), [bf-agent](../modules/bf-agent.md), [bf-common](../modules/bf-common.md), `specs/agent.md`

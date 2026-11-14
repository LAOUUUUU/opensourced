# 004: The peer list is worked out from the database and the time
**Status:** Accepted — 2026-11-10

## Context
The nodes enforce whatever peer list they are given. Something must say who is on it, and a kick that ends by itself (30 minutes, 7 days) has to take effect on the nodes without anyone running a command at the right second.

## Decision
- A kick is a row (who, why, from, until, lifted), never a flag on the device. The list is worked out each time from the devices and the kicks **at a given time**: a device is on it unless it has a kick that has started, not run out and not been lifted. Every store function takes `now` as an argument; none reads a clock. Only `main` does.
- The list's version is kept in the database. `publish(now)` compares the new list with the last one it returned and adds 1 only if they differ, whatever the cause: a device added or removed, a kick, a lift, or a kick running out.
- The list is a `bf_common::peers::PeerList`, the type the agents' own checks use, with `/32` ranges only, sorted by public key so the same devices always give the same list.

## Consequences
- A kick ending needs no job and no second write: the first `publish` after the end time puts the device back on the list and the version goes up. The poller (step 2, second part) only has to call `publish` and push the result.
- Tests need no clock and no sleeping: they pass the time they want.
- Kicks stay as history (who, why, when lifted) at the cost of a table that only grows.
- `publish` takes the database's write lock **before** it reads the devices and kicks, and writes inside the same transaction. Reading first and locking after (as the first version did) let a second program kick a device in between and have the older list stored over the newer one. Found in review.
- The version only moves when the list does, so pushing an unchanged list is harmless, and the agents' "version must not go back" rule holds across restarts of the control program.
- If the database were lost, the version would restart at 1 and the agents would refuse the list until their version is reset. The database is therefore the one thing on the web VM that must be backed up.

## Related
- [SCHEMA](../SCHEMA.md), [bf-control](../modules/bf-control.md), [decision 003](003-strict-peer-lists.md), `specs/control-core.md`

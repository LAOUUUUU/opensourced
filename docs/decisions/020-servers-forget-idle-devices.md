# 020: The servers forget a device 5 minutes after its last handshake
**Date:** 2026-11-12
**Status:** Accepted. Lao: "Yes, build it" (5 minutes). Brief: `research/idle-endpoints/RESEARCH.md`.

## Context
WireGuard keeps each peer's last IP address and port, handshake time and byte counts in the kernel's memory until the peer is removed or the interface goes down. The agent removes a peer only when it leaves the list. So anyone reading a server's memory could match a home IP address to a device, and so to an account, long after the person disconnected. The code review of the legal pages found this (decision 018). IVPN, AirVPN and OVPN all clear it by removing and re-adding a peer 180 seconds after its last handshake. There is no way to clear only the endpoint.

## Decision
- **The agent forgets idle devices.** On every 30-second pass, before the list pass, `forget_idle` removes a device and sets it again with its ranges **from the stored list**. It does this only when all of these hold:
  - WireGuard holds an address for it;
  - its last handshake is more than 300 seconds old, or it never handshook (`bf_common::wg::FORGET_IDLE_AFTER_SECS`);
  - it looked exactly the same at the last pass (address held, handshake time and bytes received, in `reconcile::Quiet`).

  It runs only while a list is stored, under the same `changing` lock as list changes. It never re-adds a peer that is not on the list; the list pass removes those. It logs only a count.
- **Two quiet passes, not one reading.** As responder, a server sets a device's address the moment its handshake arrives, but its handshake time only when the first packet after it does. A single reading could therefore catch a reconnecting device looking idle and break its new session. After a forward jump of the clock, every handshake looks old. Requiring no change at all between two passes 30 seconds apart rules out both: a reconnecting device has just changed, and a device in use keeps sending (every 25 seconds at least).
- **A forgetting that breaks halfway heals in the same pass.** If removing works but setting again fails, the list pass that runs right after puts the device back.
- **5 minutes, not 3.** Every device file has `PersistentKeepalive = 25`, so a connected device renews its handshake about every two minutes. A disconnected one is cleared within about six minutes.
- **The online window stays below it.** `BF_ONLINE_SECS` is refused at 300 or more, so a forgotten device never counts as online.
- **The website remembers "last connected".** The poller's board keeps the newest contact it has read for each device, in memory only, by public key, with no address. `seen` uses the newer of that and a server's own reading.
  - A device is dropped from the memory only after two polls in a row in which the servers that hold the current list (`in_sync`, with devices on their interface) do not list it, for example when it is removed or its account is deleted.
  - A poll with every server down, or with only an agent whose interface is still empty (a rebooted host), says nothing about who is gone and keeps the memory.
  - The public page's snapshot carries none of it.
- **The privacy page says so.** A test holds its wording, the transparency page's and the front page's to the constant.

## Consequences
- **Coming back after being forgotten is invisible.** A device that comes back after more than 5 minutes had expired keys anyway (WireGuard's sessions last at most three minutes), so it handshakes again whether or not it was forgotten.
- **Byte counts** restart when a peer is set again. The website never reads them for anything but the count of devices online.
- **"Last connected"** is now lost when the website restarts ("No connection seen since the website last started"), not when a server restarts.
- **Deploy the website first, then the agents.** The website's memory then fills from the servers before they start forgetting. The other way round, a website restart right after the agents' deploy would show "no connection seen" for every idle device.

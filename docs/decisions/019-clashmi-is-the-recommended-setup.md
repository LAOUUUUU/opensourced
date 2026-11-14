# 019: ClashMi is the recommended setup; the official apps stay one tap away
**Date:** 2026-11-12
**Status:** Accepted. On 2026-11-12, after the admin trial, Lao asked to "make clashmi defaulted like recommended". He also asked for a button under it for the app made by the protocol's makers.

## Context
- **The official apps can't switch.** The WireGuard and AmneziaWG apps hold one endpoint per tunnel and never try another port or server.
- **Every device's key is already on every server and app** (decision 013). A mihomo profile can therefore hold all of them in a fallback group, and ClashMi moves to the next connection by itself (`research/clashmi/RESEARCH.md`).
- **The trial.** `clashmi.rs` was built as an admin-only trial with a deliberately closed port first.

## Decision
- **The device-ready page leads with "Recommended: ClashMi".**
  1. Get the app: App Store, or clashmi.app for Android, Mac, Windows and Linux.
  2. Download this device's profile.
  3. Import it under My Configs, then connect.

  It says only one VPN app can be on at a time, and that ClashMi is open source, made by KaringX.
- **The official app sits underneath, in a toggle:** "Or use the official {app} app, made by the people who made {app}". It holds the same file, QR code and setup text as before, shared through `templates/device_official.html`. With no profile (no server to put in it), the official steps show on their own, as before.
- **The account page's "Get the app"** lists ClashMi first ("Recommended: it switches server and port by itself"), then WireGuard and AmneziaWG.
- **The profile is offered to everyone**, without the trial's closed port. It is still built from the new key and the board when the device is made, carried in the page as a `data:` link, and never kept.

## Consequences
- **Trust.** The recommended app is a third party's, not the protocol makers'. It is open source (GPL-3.0) and has full VPN access.
- **Speed.** It is likely slower than the official apps, because it runs WireGuard in user space. People who want the fastest connection have the official app one tap away.
- **Switching takes up to a minute,** because of the health check every 60 s.
- **Tracker blocking** depends on each connection's `remote-dns-resolve` to its server's resolver. It has not been checked on a real device yet.
- **A profile is a snapshot of the servers when the device was made.** A server added later needs the device to be added again.

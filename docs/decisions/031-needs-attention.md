# 031: The admin overview says when a server needs a reboot or has updates waiting
**Date:** 2026-11-15
**Status:** Accepted. Lao approved the brief `research/needs-attention/RESEARCH.md` ("APPVORED", 2026-11-15) after the tuning of decision 029 found both servers with a kernel installed and not running for days and Toronto with an AmneziaWG update unattended-upgrades never installs.

## Decision
- **A root timer on each VPN server, `bf-attention.timer`** (hourly, two minutes after boot; `deploy/bf-attention.{sh,service,timer}`), writes one file, `attention`: `reboot <package>` for each package in `/run/reboot-required.pkgs` (`reboot` alone when the flag names none) and `waiting <package> <version>` for each `Inst` line of `apt-get -s dist-upgrade` (a simulation on the lists `apt-daily.timer` refreshes: no lock taken, no cache written, nothing installed). At most 50 lines, replaced whole, mode 0640.
- **It writes into the folder the agents already read for the login alerts**, `/var/lib/barely-free-logins` (group `bf-logins`, decision 023), not a new folder and group as the brief said: the agents can read it already, so no new group, no new drop-in and no new agent setting. The unit has no capability and no network and may write only that folder.
- **The agent** (`LoginLog::attention`, `LoginFiles`) reads the file and adds an optional `attention` object to its signed `GET /v1/status`: `{"reboot": true, "reboot_by": [...], "waiting": [{"name", "version"}]}`. No file yet: no field. A file older than three hours (`bf_common::attention::STALE_SECS`): no field, logged once. The field is additive: an older website ignores it, and the website reads an older agent as reporting nothing.
- **The website** keeps only names that look like Debian package names (`[a-z0-9][a-z0-9+.-]`, 2–100) and versions (`[A-Za-z0-9.+~:-]`, 1–100), at most 50 (`Attention::sanitized`, the same rule the agent applies to the file); a malformed object is dropped alone, the rest of the reading stays. The admin overview adds to the server's note: "Needs a reboot (asked by linux-image-6.12.117+deb13-amd64)." and "Updates waiting: amneziawg-dkms 1.0.0-….". Nothing appears on the public pages, and nothing is emailed.
- Nothing about users is read or reported (decision 020 and the privacy policy are untouched).

## Consequences
- `deploy/deploy-agent.sh` installs the timer and runs it once before the agents restart, in the same three SSH connections.
- A reboot flag set by a package whose change was already applied live (the AmneziaWG module reload of 2026-11-15) shows until the next reboot; the package name says why.
- "Waiting" can be up to half a day behind, the age of apt's lists.
- If apt fails, the old file stays and goes stale after three hours; the agents then report nothing and log why.

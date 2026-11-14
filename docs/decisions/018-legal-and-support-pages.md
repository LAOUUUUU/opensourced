# 018: Legal, help and security pages, written out in full and tied to the code
**Date:** 2026-11-12
**Status:** Accepted. Lao asked for the site to be "legal" and tidier (2026-11-11), approved the brief ("Yes, use those") and answered:
- contact addresses: at first the recommended four, then (2026-11-12) none: "i wont do those four email address", a community server is planned;
- who runs it: Laoel Beqiri, Ontario, Canada;
- minimum age: 13, with a parent's OK under 18;
- copyright: as proposed.

Brief: `research/legal-and-support/RESEARCH.md`. Spec: `specs/legal-and-support.md`.

## Context
Sign-up opened on 2026-11-12, while the front page still promised a terms page and an abuse contact "coming soon" (decision 010 had put them first). Real VPN sites (Mullvad, IVPN, Proton VPN, Windscribe, Riseup) all publish terms, a privacy policy, a way to report abuse and security problems, and help. Most publish a record of legal requests, and a few a warrant canary. The Privacy Commissioner's guidance asks a privacy policy for:
- who is accountable, and how to reach them;
- how to get access to your information;
- how to complain;
- what goes to third parties, and why.

It also asks that the key points come first, not buried.

## Decision
- **Six static pages and `security.txt`**, served like `/cookies`: `/terms`, `/privacy`, `/abuse`, `/transparency`, `/help`, `/security`, and `/.well-known/security.txt` (RFC 9116). No scripts, no outside resources, no new crate. The terms and the privacy policy open with "the short version".
- **The header and footer are written out in each file**, as the theme buttons already were, rather than put together at serve time. Each file reads and previews on its own, `page()` still returns the file as it is, and a test holds every copy to the same markup. The cost is that a footer change touches eleven files, and the test names each one that differs.
- **The privacy policy describes the system as it is, and tests tie its numbers to the code.** Lifetimes and limits come from the `signin.rs` constants, the backup count from `deploy/bf-backup-receive`. A change in the code that breaks a promise fails a test until the page is changed too. Deleting an account is the account page's own "Delete my account" (decision 017), and the policy says the nightly copies and the pre-update copies still hold it until they are replaced.
- **No email address.** Every "contact us" on every page leads to one place, the help page's contact section (`/help#contact`). It says there is no address yet and that the planned community server will be the way to reach us; its link goes there in one edit. `security.txt`'s `Contact` is `https://barely-free.com/security` (RFC 9116 allows an https URI). Deleting an account is asked for there, after the owner has removed every device (only the signed-in owner can, which shows the account is theirs).
- **No warrant canary.** It needs a signing key and a new statement every month, and a missed update alarms people for nothing. The transparency page counts every request instead.
- **Copyright notices:** the abuse page says plainly that a notice (an exit address and a time) cannot be matched to a person, so it cannot be forwarded. Repeat infringers who can be identified another way lose access.
- **The one-time device page has no menu or footer links**, as it already had no theme buttons, so the new links cannot lose the only copy of the private key. Its logo, "Back to your account" and the app store links are older and stay.
- **On a site without sign-in,** every link to `/signin` or `/account` becomes plain text, so no page links a 404.

## Consequences
- **Abuse reports still arrive, but through the host.** Whoever is harmed looks up the server's address, which belongs to vpshostingservice.co, and the host emails its customer. The host account's inbox is therefore the real abuse channel: a complaint left unanswered there can get a server suspended.
- **When the community server exists:** put its link in `/help#contact`, and add its company to the privacy policy's "Who else handles your information" (it will see what people send there).
- **`security.txt` must be renewed** within a year (2027-11-01 now), with the security page's date.
- **Not legal advice.** The text is modelled on real providers and on the Privacy Commissioner's guidance, and no lawyer has read it.
- **One open risk:** whether Canada's notice-and-notice rule (Copyright Act s. 41.25 to 41.27) covers a VPN is unsettled. If it does, a notice we cannot forward risks statutory damages.
- **The privacy policy had to say less than first drafted** (code review, 2026-11-12). WireGuard keeps each device's last IP address until the server restarts or the device is removed. The nightly copies hold the one-day sign-in records together with the fingerprint key, so an IP fingerprint can be reversed. The servers ask Cloudflare's DNS for every name. A failed email's error can name the address. The pages now say all of this, and tests stop the old claims coming back.
- **Code changes that would let the policy promise more (not done here):**
  - the agents drop idle peers' endpoints, as some providers do;
  - the nightly copy leaves out `mail_log` and `login_codes`;
  - the log keeps only Resend's status and error name;
  - pre-update copies are pruned by age.
- **Later pieces:**
  - blocking outgoing mail on port 25 on the servers;
  - a French version.

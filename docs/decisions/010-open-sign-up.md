# 010: Anyone can make an account with a sign-in code, behind a switch that is off
**Status:** Accepted, built, not deployed — 2026-11-10 (Lao: "like u should be able just to sign up with any random email", then "Yes, build it" to the brief in `research/open-signup/RESEARCH.md`)

## Context
Only accounts an admin made (`account add --email`) could sign in. Anyone else asked for a code, saw the "Check your email" page, got no mail and, after three tries, "Too many requests". A tester hit exactly that. The log on the web VM showed no failed send after the sender moved to `barely-free.com`, so nothing was broken: it was the closed beta working as designed, and the page did not make that clear.

## Decision
- **A setting, `BC_OPEN_SIGNUP`, off by default.** `1` opens sign-up; unset or `0` is the closed beta; anything else keeps sign-in off and the log says why. Deploying the code changes nothing until it is set.
- **The account is made at the first right code**, in the transaction that uses the code up, never when it is asked for: an account cannot exist before the mailbox is proved (the same as Auth0's and Supabase's email-code sign-in). Label `member-<id>`, device limit 3, not admin, only the email's fingerprint kept.
- **Two caps per UTC day, in the code as constants:** 60 code requests for new addresses (so 30 of the 90 emails a day stay for people who already have accounts) and 20 new accounts, however made. A request refused by a cap is not written to `mail_log`. If the last place goes between asking and typing, the code is left unused and the person is told the day is full.
- **No schema change.** `mail_log.outcome = 'new'` marks the requests the first cap counts; the second cap counts `accounts.created_at`.
- **The pages say what is true.** The front page, the sign-in pages and the footer say "closed beta" only while it is off. **Changed 2026-11-14** (Lao: "remove it from beta ... just say Full release"): with sign-up open the front page badge reads "Full release · sign-up is open" (it said "Beta · sign-up is open"), and the terms no longer say the service is in beta (the limits stay, and the terms' date and change list say so). The closed wording stays for a site with sign-up off.
- **Not chosen:** Turnstile (a Cloudflare script on the same origin as sign-in and admin, and a looser content security policy; reconsider if the 20-a-day cap fills with junk); blocking throwaway-address domains (no maintained list checked); a per-node device cap (not in the code; the daily cap bounds growth to about 60 devices a day).

## Consequences
- **Abuse is the main risk.** A free VPN open to anyone will be abused; the caps bound the growth but do not stop one person making an account per email. Kicks and the 3-device limit are the tools.
- **The "same answer for everyone" rule gives way on a full day:** the "full for today" page is shown to new addresses only, so it tells that an address has no account. The alternative (a silent no-code page) is the bug that started this.
- **Anyone can make us mail any address**, up to 3 mails an hour to it (before, only known addresses). The mail says to ignore it if unasked and has no links.
- **Before turning it on:** the front page promises a terms page and an abuse contact. They do not exist; with the switch on, the page says they are "coming soon". Lao supplies the contact address.
- Turning it on is `Environment=BC_OPEN_SIGNUP=1` in the unit and a restart; turning it off is removing it.

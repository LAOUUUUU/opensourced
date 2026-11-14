# 011: Kept sessions renew on signed-in pages; the theme lives in a cookie
**Date:** 2026-11-10
**Status:** Accepted (Lao approved `specs/cookies.md`, including the auth change and schema 4, on 2026-11-10)

## Context
Lao asked for cookies "so the site remembers". The research (`research/cookies/RESEARCH.md`) compared a longer fixed login, a sliding one, remembering the email address, a theme preference and a cookie notice. Lao chose: keep today's fixed 60 days by default, with a tick box for a longer sliding login; no email cookie (browser autofill does it); a theme chosen without any script; a `/cookies` page and "uses a cookie" notes instead of a banner.

## Decision
- **A kept session is renewed only by a signed-in page that answered.** The `/account` pages and the admin pages, with a status under 400. Not the sign-in pages, not `/theme`, not a 405 or a refused form: those are not the person using their account, and the spec says "GET /account or any signed-in POST". Renewal gives 60 days from now, at most once a day (a renewal is a database write), never past 365 days from sign-in (under Chrome's 400-day cookie cap). The cookie is re-sent with the time left.
- **Renewal runs after the handler, not before.** A sign-out has then already ended the session and a sign-in has already replaced it, so neither can be renewed; a reply that sets the session cookie itself keeps its own.
- **Read first, write only when due, and only if unchanged.** A plain `SELECT`, then `UPDATE ... WHERE id = ? AND expires_at = <read value>`. Most requests renew nothing and should not take the write lock.
- **The theme is a `__Host-` cookie, `HttpOnly`, `SameSite=Lax`, one year.** No script can read or set it, so the server draws each page in the chosen theme (`data-theme` on `<html>`). `Lax` so a link from another site still shows the chosen colours; it says nothing about anyone. "System" is no cookie at all.
- **`/theme` needs the same-origin check but no session token.** The worst a forged request could do is change the colours, and the check refuses other sites anyway. The redirect target must be one of a fixed list of paths.
- **The public pages now allow a form to this site (`form-action 'self'`) and send `Referrer-Policy: same-origin`.** The theme buttons are a form on every page. With `no-referrer` browsers write `Origin: null` on a form post, which the same-origin check must refuse (found the same way for the sign-in pages, decision in `docs/modules/bf-control.md`). `same-origin` still sends nothing to other sites.

## Consequences
- A stolen kept-session cookie stays useful for up to a year, as long as it is used. "Sign out everywhere" and session-id rotation are open follow-ups.
- Schema 4 cannot be read by an older binary; a rollback needs the database backup.
- Public pages differ per visitor, so they carry `Vary: Cookie` and `private, no-cache` (Cloudflare ignores `Vary: Cookie`).
- Pressing a theme button reloads the page, losing anything half typed in a form on it; the one-time device page has no theme buttons.

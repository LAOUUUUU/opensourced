# 021: Search engines: a sitemap, canonical links and link previews, tied to the pages by tests
**Date:** 2026-11-12
**Status:** Accepted. Lao asked for "a sitemap and all the stuff and like seo and stuff" (2026-11-12) and approved the brief with "Yes, build it".

Brief: `research/seo/RESEARCH.md`. Spec: `specs/seo.md`. (Number 020 is the other session's, `020-servers-forget-idle-devices.md`.)

## Context
Sign-up opened on 2026-11-12, so strangers are being sent to the site. It told search engines nothing: no sitemap, a `robots.txt` with no sitemap line, no canonical address (`www.barely-free.com` answers 200 with a copy of every page), no preview text for a shared link, no machine-readable site name. `/check` prints the visitor's own address, which for a crawler is the crawler's.

## Decision
- **`/sitemap.xml` lists the eight public pages**, by their `https://barely-free.com/...` addresses, with **no `lastmod`, `priority` or `changefreq`**. Google ignores the last two and uses `lastmod` only when it is "consistently and verifiably" accurate; nothing here can prove that, and a date that is merely "today" is worse than none. Listed: `/`, `/help`, `/terms`, `/privacy`, `/abuse`, `/transparency`, `/security`, `/cookies`. Left out: `/check`, the sign-in side, the admin panel, `/healthz`, `security.txt`, the 404 page.
- **`robots.txt` allows everything and names the sitemap. It has no `Disallow` and never names `/admin`.** Google never sees a `noindex` on a page it may not fetch, so a `Disallow` for the sign-in pages would undo their `noindex`; and the site answers `/admin` like any unknown path on purpose, so a line for it would announce a page that is otherwise hidden. Tests refuse both.
- **One self-referencing canonical per public page**, absolute, on the bare name. It is a signal and not a command (Google says so), but it is the one thing the program can do about `www` without touching how forms work on either name (`BC_ORIGINS` lists both). A Cloudflare redirect from `www` is the stronger signal and is left to Lao, optionally.
- **`/check` is `noindex` and stays crawlable**, with no canonical and no sitemap entry. An "am I on a VPN?" page can attract searches, so this is easy to reverse later.
- **Link previews are plain Open Graph and Twitter tags built from each page's own title, description and canonical**, `twitter:card` = `summary`, no image yet. A test, not a generator at serve time, holds the copies equal, as with the header and footer (decision 018). The front page's open-sign-up swap (`OPEN_WORDING`) changes `og:description` together with the description.
- **`WebSite` data on the front page only** (`name` "Barely-free", `alternateName` `["barely-free.com"]`, `url`), the way Google reads a site name. No description (nothing to keep in step) and no operator name. **Checked in a real browser before it was built in:** a page served with this site's exact policy (`default-src 'none'`) showed a console error for a control inline `<script>` and none for the `application/ld+json` block, and the page could read and parse it. It is data, not a program.
- **The "no scripts" tests now count scripts that would run** (`runnable_scripts`): every `<script` except the one `type="application/ld+json"` block. A script that runs, on any public page, still fails them. The "only address outside this site is Ko-fi" test treats the exact host `https://barely-free.com` (and `/...` under it) as this site; `www`, plain `http` and a longer name that starts with it still count as outside.
- **A new page file must be decided about.** A test scans `web/` and fails until the file is in the sitemap list or named in `KEPT_OUT`.

## Consequences
- **Each public page's head gains seven lines** (a canonical and six preview tags), and the front page one more. Nine HTML files, `web.rs` and one new test file changed; no new dependency, no visible change, no new header, cookie or request.
- **Search engines may index the site slowly** for weeks: a new domain with few links often waits. The sitemap and Search Console speed discovery, not ranking. "Free VPN" is among the most competitive terms; the realistic win is people who search for the name.
- **Cloudflare keeps `robots.txt` and the sitemap at its edge** (the live `robots.txt` came back with a 4-hour `max-age` against the code's 1 hour), so a change can show a few hours late.
- **Lao's own steps** (not the program's): Google Search Console as a Domain property with a DNS TXT record in the Cloudflare account, then submit the sitemap; the same in Bing Webmaster Tools; optionally the `www` redirect. README, "Search engines".
- **Not done, on purpose:** IndexNow (a key file, outgoing calls the website never makes, Google not confirmed as a participant, eight pages found by sitemap anyway), `Organization` data (no promised result), `hreflang` (English only; do it with a French version), analytics, blocking AI crawlers (a policy choice).
- **Later, separately:** a plain 1200×630 share image (`og:image`, `twitter:card` = `summary_large_image`). It needs a binary file served (`Page.body` is a `&str`) and Lao's look at the picture first.
- **Merge:** the other session has uncommitted edits to `web.rs`, `web/index.html`, `privacy.html`, `transparency.html` and `src/web/tests/legal.rs`; expect a small conflict in the page heads and in the `mod seo;` line when both land.

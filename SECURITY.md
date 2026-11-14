# Security policy

Barely-free is a free VPN run by one person. If you find a security problem in it, please tell us privately first, so it can be fixed before anyone can misuse it.

## How to report

Use GitHub's private form for this repository: **[Report a vulnerability](https://github.com/LAOUUUUU/opensourced/security/advisories/new)**. It needs a free GitHub account, and only you and the maintainer can read what you send. Please do not open a public issue, pull request or discussion about it.

Send what the problem is, how to make it happen, and what someone could do with it. Plain text is best.

This file follows the policy on the website, <https://barely-free.com/security>, which `https://barely-free.com/.well-known/security.txt` points to. If the two ever differ, the website's page is the one in force.

## In scope

- The website, barely-free.com: signing in, the account pages and the device setups they make.
- The VPN servers, as reached through a Barely-free setup: for example one device reaching another, traffic or DNS leaking, or getting around a kick.
- The code in this repository.

## Not in scope

- Denial of service and load testing.
- Spam, phishing or tricking us or our users.
- Scanner output with no real effect shown.
- Problems in Cloudflare, Resend, Ko-fi, the hosting company, or the WireGuard and AmneziaWG apps: please report those to them.

## Please

- Use only your own account and devices. Do not read, change or delete anyone else's data; if you reach some by accident, stop and tell us what you saw.
- Do not slow down or interrupt the service for anyone else.
- Give us 90 days to fix the problem before you publish it, or tell us why you think that is too long.

## What we promise

- A reply within 7 days, and news as the fix goes on.
- If you follow this policy in good faith, we will not take legal action against you or report you for your research.
- Thanks on the website's security page once the fix is out, if you want.
- There is no reward: Barely-free has no money beyond donations for its servers.

## Supported versions

Only what runs at barely-free.com today. The public repository is a copy of the code published at a release, so it can be a little behind the site; older copies get no fixes.

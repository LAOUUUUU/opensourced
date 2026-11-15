#!/bin/bash
# Barely-free: what on this server needs Lao's attention, for the admin overview.
# Decision 031, research/needs-attention/RESEARCH.md.
#
# Runs on the VPN servers as root once an hour (bf-attention.timer). It writes one file into
# the folder the agents already read for the login alerts, /var/lib/barely-free-logins
# (group bf-logins), replaced whole so a reader never sees half of it:
#   reboot <package>             for each package in /run/reboot-required.pkgs (`reboot` alone
#                                when the flag names none);
#   waiting <package> <version>  for each package apt would install or upgrade, from
#                                `apt-get -s dist-upgrade` on the lists apt-daily.timer
#                                refreshes (a simulation: nothing is installed or locked).
# At most 50 lines. If apt fails the old file stays; it goes stale after three hours and the
# agents then report nothing and log why. No network, writes nothing else. Installed as
# /usr/local/lib/barely-free/bf-attention.sh by deploy/deploy-agent.sh.
set -euo pipefail
umask 027
export LC_ALL=C

dir=${BF_ATTENTION_DIR:-/var/lib/barely-free-logins}
run=${BF_RUN_DIR:-/run}

out=$(mktemp "$dir/.attention.XXXXXX")
trap 'rm -f "$out"' EXIT
{
  if [ -e "$run/reboot-required" ]; then
    if [ -s "$run/reboot-required.pkgs" ]; then
      sort -u "$run/reboot-required.pkgs" | awk 'NF == 1 { print "reboot " $1 }'
    else
      echo reboot
    fi
  fi
  # No lock (apt-daily may hold it) and no cache file (the system is read-only here).
  apt-get -s -q -o Debug::NoLocking=1 -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= \
    dist-upgrade </dev/null 2>/dev/null |
    awk '$1 == "Inst" { rest = $0; sub(/^[^(]*\(/, "", rest); split(rest, v, " "); print "waiting " $2 " " v[1] }'
} | awk 'NR <= 50' >"$out"

# mktemp makes it 0600; the group reads it.
chmod 0640 "$out"
mv -f "$out" "$dir/attention"

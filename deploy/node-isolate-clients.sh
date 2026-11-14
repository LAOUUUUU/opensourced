#!/bin/sh
# Stops the devices on a node from reaching each other.
#
# Every device on a node shares one VPN interface (awg0 on Toronto, wg0 on Dallas), and the
# node's first FORWARD rule accepts everything that comes in from it, so one customer's device
# could open connections to another customer's device (10.77.0.2 to 10.77.0.3, and the old
# 10.66.x devices). This adds one rule in front of that accept:
#
#   iptables -I FORWARD 1 -i <interface> -o <interface> -j DROP
#
# which drops traffic that comes in from the VPN and would go straight back out of it. Traffic
# to the internet, and the replies, are untouched. Devices of one account cannot reach each
# other either: the VPN is not a private network between them.
#
# It finds the interface itself (the one that has 10.77.0.1/16), applies the rule to the running
# firewall (nobody is disconnected) and adds the same two lines to the interface's file, after
# its last PostUp and PostDown lines, so a restart brings it back. The new file is checked with
# wg-quick/awg-quick before it replaces the old one, and a copy of the old one is kept as
# <file>.before-isolation. Safe to run again: it changes only what is missing.
#
# Run it yourself, once per node:
#   deploy/node-isolate-clients.sh root@<node ip> -i ~/.ssh/<key> -o IdentitiesOnly=yes
#
# To undo it on a node: delete the rule (iptables -D FORWARD -i <if> -o <if> -j DROP) and put
# the .before-isolation copy back.
set -eu

host=${1:?usage: deploy/node-isolate-clients.sh <user@host> [ssh options...]}
shift

ssh "$@" "$host" 'sh -s' <<'REMOTE'
set -eu
umask 077

dev=
for d in awg0 wg0; do
  if ip -4 addr show dev "$d" 2>/dev/null | grep -q 'inet 10\.77\.0\.1/16'; then
    dev=$d
    break
  fi
done
[ -n "$dev" ] || { echo "neither awg0 nor wg0 has 10.77.0.1/16 here (deploy/node-network.sh gives it); nothing was changed" >&2; exit 1; }

case $dev in
  awg0) conf=/etc/amnezia/amneziawg/awg0.conf; quick=awg-quick ;;
  *) conf=/etc/wireguard/wg0.conf; quick=wg-quick ;;
esac
[ -f "$conf" ] || { echo "$conf is not there; nothing was changed" >&2; exit 1; }

up='PostUp = iptables -I FORWARD 1 -i %i -o %i -j DROP'
down='PostDown = iptables -D FORWARD -i %i -o %i -j DROP'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
new="$tmp/$dev.conf"

# The file, so a restart of the interface brings the same back. The new PostUp has to come
# after every existing one: each of them inserts at the top of FORWARD, so the last one to run
# ends up first, and this one must be it.
if grep -qxF "$up" "$conf" && grep -qxF "$down" "$conf"; then
  echo "file:     $conf already has the rule"
else
  grep -q '^PostUp = ' "$conf" && grep -q '^PostDown = ' "$conf" \
    || { echo "$conf has no PostUp and PostDown lines to put the rule after; nothing was changed" >&2; exit 1; }
  awk -v up="$up" -v down="$down" '
    { line[NR] = $0 }
    /^PostUp = /   { lastup = NR }
    /^PostDown = / { lastdown = NR }
    END {
      for (i = 1; i <= NR; i++) {
        print line[i]
        if (i == lastup) print up
        if (i == lastdown) print down
      }
    }
  ' "$conf" > "$new"
  "$quick" strip "$new" >/dev/null 2>&1 \
    || { echo "$quick does not accept the new file; nothing was changed" >&2; exit 1; }
  [ -e "$conf.before-isolation" ] || cp "$conf" "$conf.before-isolation"
  cat "$new" > "$conf"
  echo "file:     added the rule to $conf (the old one is $conf.before-isolation)"
fi

# The running firewall, in front of the accept.
first=$(iptables -S FORWARD | sed -n '/^-A FORWARD /{p;q;}')
if [ "$first" = "-A FORWARD -i $dev -o $dev -j DROP" ]; then
  echo "firewall: the rule is already first in FORWARD"
else
  while iptables -C FORWARD -i "$dev" -o "$dev" -j DROP 2>/dev/null; do
    iptables -D FORWARD -i "$dev" -o "$dev" -j DROP
  done
  iptables -I FORWARD 1 -i "$dev" -o "$dev" -j DROP
  echo "firewall: put the rule first in FORWARD"
fi

echo "interface: $dev"
echo "FORWARD, first rules:"
iptables -S FORWARD | sed -n '1,4p'
REMOTE

#!/bin/sh
# Keeps VPN users' traffic out of the admin's tailnet (decision 024).
#
# Tailscale's own FORWARD rule (ts-forward, first in FORWARD) accepts everything that leaves
# on tailscale0, so a packet a VPN user sends to a 100.x address, or to Tailscale's DNS at
# 100.100.100.100, would be passed into the tailnet with the user's own source address.
# The other devices drop it (it is not the server's address), but nothing on the server
# stopped it. This drops it as it arrives, in the raw table, which Tailscale never touches:
#
#   iptables  -t raw -A PREROUTING -i <vpn interface> -d 100.64.0.0/10 -j DROP
#   ip6tables -t raw -A PREROUTING -i <vpn interface> -d fd7a:115c:a1e0::/48 -j DROP
#
# for each VPN interface the server has (wg0, awg0). The rules go on the running firewall
# first, which proves the exact commands work here; only then are the same lines added to
# each interface's file (after its last PostUp and PostDown, with %i), so a restart brings
# them back. Each new file is checked with wg-quick/awg-quick before it replaces the old one,
# and a copy of the old one is kept as <file>.before-tailnet-guard. Safe to run again: it
# adds only what is missing. Nobody is disconnected. One SSH connection.
#
# Run it yourself, once per node:
#   deploy/node-tailnet-guard.sh root@<node ip> -i ~/.ssh/<key> -o IdentitiesOnly=yes
#
# To undo it on a node: delete the rules (the same commands with -D) and put the
# .before-tailnet-guard copies back.
set -eu

host=${1:?usage: deploy/node-tailnet-guard.sh <user@host> [ssh options...]}
shift

ssh "$@" "$host" 'sh -s' <<'REMOTE'
set -eu
umask 077
command -v iptables >/dev/null 2>&1 && command -v ip6tables >/dev/null 2>&1 \
  || { echo "iptables and ip6tables are needed here; nothing was changed" >&2; exit 1; }

up4='PostUp = iptables -t raw -A PREROUTING -i %i -d 100.64.0.0/10 -j DROP'
up6='PostUp = ip6tables -t raw -A PREROUTING -i %i -d fd7a:115c:a1e0::/48 -j DROP'
down4='PostDown = iptables -t raw -D PREROUTING -i %i -d 100.64.0.0/10 -j DROP'
down6='PostDown = ip6tables -t raw -D PREROUTING -i %i -d fd7a:115c:a1e0::/48 -j DROP'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
found=0
for dev in wg0 awg0; do
  ip link show dev "$dev" >/dev/null 2>&1 || continue
  found=1
  case $dev in
    awg0) conf=/etc/amnezia/amneziawg/awg0.conf; quick=awg-quick ;;
    *) conf=/etc/wireguard/wg0.conf; quick=wg-quick ;;
  esac
  [ -f "$conf" ] || { echo "$dev is up but $conf is not there; stopped" >&2; exit 1; }

  # The running firewall first: if a command fails here, no file has been changed.
  if ! iptables -t raw -C PREROUTING -i "$dev" -d 100.64.0.0/10 -j DROP 2>/dev/null; then
    iptables -t raw -A PREROUTING -i "$dev" -d 100.64.0.0/10 -j DROP
  fi
  if ! ip6tables -t raw -C PREROUTING -i "$dev" -d fd7a:115c:a1e0::/48 -j DROP 2>/dev/null; then
    ip6tables -t raw -A PREROUTING -i "$dev" -d fd7a:115c:a1e0::/48 -j DROP
  fi
  echo "firewall: $dev to the tailnet is dropped"

  # The file, so a restart brings the same back.
  # The lines still missing, one file for the PostUp ones and one for the PostDown ones.
  : >"$tmp/up"
  : >"$tmp/down"
  for line in "$up4" "$up6"; do
    grep -qxF "$line" "$conf" || printf '%s\n' "$line" >>"$tmp/up"
  done
  for line in "$down4" "$down6"; do
    grep -qxF "$line" "$conf" || printf '%s\n' "$line" >>"$tmp/down"
  done
  if [ ! -s "$tmp/up" ] && [ ! -s "$tmp/down" ]; then
    echo "file:     $conf already has the lines"
    continue
  fi
  grep -q '^PostUp = ' "$conf" && grep -q '^PostDown = ' "$conf" \
    || { echo "$conf has no PostUp and PostDown lines to put the rules after; stopped" >&2; exit 1; }
  new="$tmp/$dev.conf"
  awk -v upfile="$tmp/up" -v downfile="$tmp/down" '
    { line[NR] = $0 }
    /^PostUp = /   { lastup = NR }
    /^PostDown = / { lastdown = NR }
    END {
      for (i = 1; i <= NR; i++) {
        print line[i]
        if (i == lastup) while ((getline l < upfile) > 0) print l
        if (i == lastdown) while ((getline l < downfile) > 0) print l
      }
    }
  ' "$conf" >"$new"
  "$quick" strip "$new" >/dev/null 2>&1 \
    || { echo "$quick does not accept the new $conf; it was not changed (the running rules stay)" >&2; exit 1; }
  [ -e "$conf.before-tailnet-guard" ] || cp -p "$conf" "$conf.before-tailnet-guard"
  cat "$new" >"$conf"
  echo "file:     added the lines to $conf (the old one is $conf.before-tailnet-guard)"
done
[ "$found" = 1 ] || { echo "no wg0 or awg0 here; nothing was changed" >&2; exit 1; }

echo "raw PREROUTING:"
iptables -t raw -S PREROUTING
ip6tables -t raw -S PREROUTING
REMOTE

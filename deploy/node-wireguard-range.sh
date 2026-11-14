#!/bin/sh
# Moves a server's WireGuard (wg0) from 10.77.0.0/16 to 10.78.0.0/16, so AmneziaWG can take
# 10.77 on the same server (specs/dual-protocol.md). For Dallas, before
# deploy/node-add-protocol.sh adds AmneziaWG there.
#
# Run it yourself:
#   deploy/node-wireguard-range.sh root@dallas.example.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes
#
# The running interface is changed in place (nobody is disconnected; the older 10.66 range
# and its peers are not touched) and so is /etc/wireguard/wg0.conf (the earlier one is kept
# as wg0.conf.before-dual). Safe to run again: a wg0 already on 10.78 is left alone.
# Afterwards, on the VM: bf-control node set-protocol <this server's agent> wireguard, so
# the agent is sent the list in 10.78.
set -eu

host=${1:?usage: deploy/node-wireguard-range.sh <user@host> [ssh options...]}
shift

ssh "$@" "$host" 'sh -s' <<'REMOTE'
set -eu
conf=/etc/wireguard/wg0.conf
[ -f "$conf" ] || { echo "$conf is not there" >&2; exit 1; }
systemctl is-active --quiet wg-quick@wg0 || { echo "wg0 is not running: not touching it" >&2; exit 1; }
wan=$(ip -o route get 1.1.1.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p')
[ -n "$wan" ] || { echo "cannot tell which interface reaches the internet" >&2; exit 1; }

# Done means done in the file AND on the running interface: a run that stopped half way is
# finished by the next one.
file_done=no
grep -q '10\.78\.0\.1/16' "$conf" && ! grep -q '10\.77\.0\.1/16' "$conf" && file_done=yes
live_done=no
if ip -4 addr show dev wg0 | grep -q 'inet 10\.78\.0\.1/16' \
  && ! ip -4 addr show dev wg0 | grep -q 'inet 10\.77\.0\.1/16' \
  && ! iptables -t nat -C POSTROUTING -s 10.77.0.0/16 -o "$wan" -j MASQUERADE 2>/dev/null; then
  live_done=yes
fi
if [ "$file_done" = yes ] && [ "$live_done" = yes ]; then
  echo "wg0 is already on 10.78.0.1/16: nothing to do"
  exit 0
fi

if [ "$file_done" = no ]; then
  grep -q '^Address = .*10\.77\.0\.1/16' "$conf" \
    || { echo "wg0.conf has no 10.77.0.1/16 address to move: not touching it" >&2; exit 1; }
  # The file first, checked before anything live changes.
  [ -e "$conf.before-dual" ] || cp -p "$conf" "$conf.before-dual"
  sed -e 's#10\.77\.0\.1/16#10.78.0.1/16#g' -e 's#10\.77\.0\.0/16#10.78.0.0/16#g' "$conf" > "$conf.new"
  chmod 0600 "$conf.new"
  # wg-quick takes the interface name from the file name, so check it as wg0.conf.
  check=$(mktemp -d)
  cp "$conf.new" "$check/wg0.conf"
  if ! wg-quick strip "$check/wg0.conf" >/dev/null; then
    rm -rf "$check" "$conf.new"
    echo "the changed wg0.conf does not parse: nothing was changed" >&2
    exit 1
  fi
  rm -rf "$check"
  mv "$conf.new" "$conf"
fi

# The running interface: the new address and NAT first, then the old ones go.
ip -4 addr show dev wg0 | grep -q 'inet 10\.78\.0\.1/16' || ip addr add 10.78.0.1/16 dev wg0
iptables -t nat -C POSTROUTING -s 10.78.0.0/16 -o "$wan" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 10.78.0.0/16 -o "$wan" -j MASQUERADE
! ip -4 addr show dev wg0 | grep -q 'inet 10\.77\.0\.1/16' || ip addr del 10.77.0.1/16 dev wg0
while iptables -t nat -C POSTROUTING -s 10.77.0.0/16 -o "$wan" -j MASQUERADE 2>/dev/null; do
  iptables -t nat -D POSTROUTING -s 10.77.0.0/16 -o "$wan" -j MASQUERADE
done

echo "wg0:   $(ip -brief -4 addr show dev wg0 | tr -s ' ')"
echo "nat:   $(iptables -t nat -S POSTROUTING | grep -c '10.78.0.0/16') rule(s) for 10.78.0.0/16"
echo "file:  $conf (the earlier one is $conf.before-dual)"
echo
echo "Now, on the VM: bf-control node set-protocol <this server's agent, e.g. dallas> wireguard"
REMOTE

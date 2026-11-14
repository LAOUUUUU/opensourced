#!/bin/sh
# Gives a node's WireGuard the network the control program hands devices addresses from:
# 10.77.0.1/16 on wg0 (the server's address; devices get 10.77.0.2 and up) and NAT for that
# range. The older 10.66.x network stays for now. Safe to run again: it changes only what is
# missing, applies it to the running interface (nobody is disconnected) and writes it to
# /etc/wireguard/wg0.conf (a copy is kept as wg0.conf.before-10.77).
#
# Run it yourself, once per node:
#   deploy/node-network.sh root@<node ip> -i ~/.ssh/<key> -o IdentitiesOnly=yes
set -eu

host=${1:?usage: deploy/node-network.sh <user@host> [ssh options...]}
shift

ssh "$@" "$host" 'sh -s' <<'REMOTE'
set -eu
conf=/etc/wireguard/wg0.conf
wan=$(ip -o route get 1.1.1.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p')
[ -n "$wan" ] || { echo "cannot tell which interface reaches the internet" >&2; exit 1; }
[ -f "$conf" ] || { echo "$conf is not there" >&2; exit 1; }
cp -n "$conf" "$conf.before-10.77" 2>/dev/null || true

# The running interface.
ip -4 addr show dev wg0 | grep -q 'inet 10\.77\.0\.1/16' || ip addr add 10.77.0.1/16 dev wg0
iptables -t nat -C POSTROUTING -s 10.77.0.0/16 -o "$wan" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 10.77.0.0/16 -o "$wan" -j MASQUERADE

# The file, so a restart of wg0 brings the same back.
grep -q '10\.77\.0\.1/16' "$conf" || sed -i 's#^Address = \(.*\)$#Address = \1, 10.77.0.1/16#' "$conf"
grep -q '10\.77\.0\.0/16' "$conf" || {
  sed -i "/^PostUp = /s#\$#; iptables -t nat -A POSTROUTING -s 10.77.0.0/16 -o $wan -j MASQUERADE#" "$conf"
  sed -i "/^PostDown = /s#\$#; iptables -t nat -D POSTROUTING -s 10.77.0.0/16 -o $wan -j MASQUERADE#" "$conf"
}
wg-quick strip wg0 >/dev/null || { echo "wg0.conf no longer parses; the original is $conf.before-10.77" >&2; exit 1; }

echo "wg0:      $(ip -brief -4 addr show dev wg0 | tr -s ' ')"
echo "route:    $(ip route show 10.77.0.0/16)"
echo "nat:      $(iptables -t nat -S POSTROUTING | grep '10.77.0.0/16')"
echo "forward:  $(sysctl -n net.ipv4.ip_forward)"
echo "peers:    $(wg show wg0 peers | wc -l) (unchanged)"
grep -E '^Address ' "$conf"
grep -c '10.77.0.0/16' "$conf" | sed 's/^/rules in wg0.conf mentioning 10.77.0.0\/16: /'
REMOTE

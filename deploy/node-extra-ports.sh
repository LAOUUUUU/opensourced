#!/bin/sh
# Lets the VPN in on extra ports, for networks that block the usual ones (specs/dual-protocol.md):
#   WireGuard (wg0, UDP 51820)  also on UDP 53 and 123
#   AmneziaWG (awg0, UDP 443)   also on UDP 4500
# Each extra port is redirected to the interface's own port, only for traffic that arrives on
# the public interface (nothing inside the tunnels changes, and replies to the server's own
# DNS and time requests are not touched: they belong to connections it started). A device
# uses an extra port by changing the number at the end of Endpoint in its app.
#
# For interfaces made before deploy/node-add-protocol.sh had this built in (Toronto's awg0,
# Dallas's wg0). Run it yourself, once per server; safe to run again:
#   deploy/node-extra-ports.sh root@<server ip> -i ~/.ssh/your_key -o IdentitiesOnly=yes
# A running interface gets the redirects at once and in its file (the earlier file is kept as
# <file>.before-ports); an interface that is not running is left alone.
set -eu

host=${1:?usage: deploy/node-extra-ports.sh <user@host> [ssh options...]}
shift

ssh "$@" "$host" 'sh -s' <<'REMOTE'
set -eu
wan=$(ip -o route get 1.1.1.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p')
[ -n "$wan" ] || { echo "cannot tell which interface reaches the internet" >&2; exit 1; }

ports() { # dev quick conf extra-ports...
  dev=$1; quick=$2; conf=$3; shift 3
  if ! systemctl is-active --quiet "$quick@$dev"; then
    echo "$dev: not running, left alone"
    return 0
  fi
  [ -f "$conf" ] || { echo "$dev runs but $conf is not there: not touching it" >&2; exit 1; }
  port=$(sed -n 's/^ListenPort *= *\([0-9][0-9]*\).*/\1/p' "$conf" | head -n 1)
  [ -n "$port" ] || { echo "$conf has no ListenPort: not touching it" >&2; exit 1; }
  missing=""
  for extra in "$@"; do
    grep -qxF "PostUp = iptables -t nat -A PREROUTING -i $wan -p udp --dport $extra -j REDIRECT --to-ports $port" "$conf" \
      || missing="$missing $extra"
  done
  if [ -n "$missing" ]; then
    [ -e "$conf.before-ports" ] || cp -p "$conf" "$conf.before-ports"
    # Into the [Interface] section, right after its ListenPort line.
    awk -v wan="$wan" -v port="$port" -v extras="$missing" '
      { print }
      !done && /^ListenPort *=/ {
        n = split(extras, e, " ")
        for (i = 1; i <= n; i++) {
          printf "PostUp = iptables -t nat -A PREROUTING -i %s -p udp --dport %s -j REDIRECT --to-ports %s\n", wan, e[i], port
          printf "PostDown = iptables -t nat -D PREROUTING -i %s -p udp --dport %s -j REDIRECT --to-ports %s\n", wan, e[i], port
        }
        done = 1
      }' "$conf" > "$conf.new"
    chmod 0600 "$conf.new"
    check=$(mktemp -d)
    cp "$conf.new" "$check/$dev.conf"
    if ! $quick strip "$check/$dev.conf" >/dev/null; then
      rm -rf "$check" "$conf.new"
      echo "$dev: the changed file does not parse: nothing was changed" >&2
      exit 1
    fi
    rm -rf "$check"
    mv "$conf.new" "$conf"
  fi
  for extra in "$@"; do
    iptables -t nat -C PREROUTING -i "$wan" -p udp --dport "$extra" -j REDIRECT --to-ports "$port" 2>/dev/null \
      || iptables -t nat -A PREROUTING -i "$wan" -p udp --dport "$extra" -j REDIRECT --to-ports "$port"
  done
  echo "$dev: UDP $port, and $* from outside"
}

ports wg0 wg-quick /etc/wireguard/wg0.conf 53 123
ports awg0 awg-quick /etc/amnezia/amneziawg/awg0.conf 4500
REMOTE

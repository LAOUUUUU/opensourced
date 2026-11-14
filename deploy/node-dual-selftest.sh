#!/bin/sh
# Checks, on a server that has both WireGuard and AmneziaWG (deploy/node-add-protocol.sh),
# what no published source covers (research/dual-protocol/RESEARCH.md): one client key can be
# a peer of a WireGuard interface and of an AmneziaWG interface on the same server at the same
# time, each with its own address, and both handshake.
#
# It uses four throwaway interfaces on loopback (bfdwg0/bfdwg1, bfdawg0/bfdawg1, UDP
# 51990-51993), never touches wg0 or awg0 and removes everything when it ends. Run it
# yourself, on Dallas first:
#   ssh -i ~/.ssh/your_key -o IdentitiesOnly=yes root@dallas.example.ts.net 'sh -s' < deploy/node-dual-selftest.sh
#
# It prints PASS or FAIL for each check and exits 1 if any failed.
set -eu
D=$(mktemp -d /root/bf-dual.XXXXXX)
cleanup() {
  for dev in bfdwg0 bfdwg1 bfdawg0 bfdawg1; do ip link del "$dev" 2>/dev/null || true; done
  rm -rf "$D"
}
trap cleanup EXIT
failed=0
check() { if "$@"; then echo "PASS: $label"; else echo "FAIL: $label"; failed=1; fi; }

label="the amneziawg kernel module is loaded (no userspace fallback)"
check test -d /sys/module/amneziawg
[ "$failed" = 0 ] || exit 1

umask 077
wg genkey > "$D/server-wg"
awg genkey > "$D/server-awg"
wg genkey > "$D/client"
client=$(wg pubkey < "$D/client")
server_wg=$(wg pubkey < "$D/server-wg")
server_awg=$(awg pubkey < "$D/server-awg")
# The parameters every AmneziaWG device gets (AMNEZIA_PARAMS in crates/bf-control/src/app.rs).
params='Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 20
H1 = 1000000001
H2 = 1000000002
H3 = 1000000003
H4 = 1000000004'

# The server side: the same client key on both, each with its own address.
printf '[Interface]\nPrivateKey = %s\nListenPort = 51990\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.250.0.2/32\n' \
  "$(cat "$D/server-wg")" "$client" > "$D/bfdwg0.conf"
printf '[Interface]\nPrivateKey = %s\nListenPort = 51992\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.251.0.2/32\n' \
  "$(cat "$D/server-awg")" "$params" "$client" > "$D/bfdawg0.conf"
# The client side: one key, two tunnels, as a phone that has both setups.
printf '[Interface]\nPrivateKey = %s\nListenPort = 51991\n\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:51990\nAllowedIPs = 10.250.0.1/32\nPersistentKeepalive = 1\n' \
  "$(cat "$D/client")" "$server_wg" > "$D/bfdwg1.conf"
printf '[Interface]\nPrivateKey = %s\nListenPort = 51993\n%s\n\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:51992\nAllowedIPs = 10.251.0.1/32\nPersistentKeepalive = 1\n' \
  "$(cat "$D/client")" "$params" "$server_awg" > "$D/bfdawg1.conf"

ip link add bfdwg0 type wireguard
ip link add bfdwg1 type wireguard
ip link add bfdawg0 type amneziawg
ip link add bfdawg1 type amneziawg
wg setconf bfdwg0 "$D/bfdwg0.conf"
wg setconf bfdwg1 "$D/bfdwg1.conf"
awg setconf bfdawg0 "$D/bfdawg0.conf"
awg setconf bfdawg1 "$D/bfdawg1.conf"
for dev in bfdwg0 bfdwg1 bfdawg0 bfdawg1; do ip link set "$dev" up; done

label="the client key is a peer of both server interfaces"
check sh -c "wg show bfdwg0 peers | grep -qx '$client' && awg show bfdawg0 peers | grep -qx '$client'"

sleep 4
handshake() { # tool device: the latest handshake with the client, in Unix seconds (0: none)
  "$1" show "$2" latest-handshakes | awk -v k="$client" '$1 == k { print $2 }'
}
label="WireGuard handshakes with that key"
check test "$(handshake wg bfdwg0)" -gt 0
label="AmneziaWG handshakes with that key, at the same time"
check test "$(handshake awg bfdawg0)" -gt 0
exit "$failed"

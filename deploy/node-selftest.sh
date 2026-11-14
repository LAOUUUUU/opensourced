#!/bin/sh
# Checks a bf-agent build against a REAL WireGuard on a node, on two throwaway interfaces
# (wgtest0 and wgtest1). It never touches wg0 and cleans up after itself. It also speaks the
# signing protocol with openssl and curl, independently of the Rust code. Re-run it after any
# change to how the agent talks to `wg`.
#
# From the repo root:
#   cargo zigbuild --release --target x86_64-unknown-linux-musl -p bf-agent
#   scp <ssh opts> target/x86_64-unknown-linux-musl/release/bf-agent <user@node>:/root/bf-agent-test
#   ssh <ssh opts> <user@node> 'chmod 755 /root/bf-agent-test && sh -s' < deploy/node-selftest.sh
#
# Read the output: every step says what it expects. It needs curl, openssl, python3, wg and ip
# on the node.
set -eu
BIN=/root/bf-agent-test
D=$(mktemp -d /root/bf-scratch.XXXXXX)
PORT=9879  # not 9871: a server with both protocols runs its second agent there
URL=http://127.0.0.1:$PORT
PID=""
cleanup() {
  if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; fi
  ip link del wgtest0 2>/dev/null || true
  ip link del wgtest1 2>/dev/null || true
  rm -rf "$D" "$BIN"
}
trap cleanup EXIT

step() { printf '\n=== %s\n' "$1"; }

call() { # method path [body]: prints the answer body, then "HTTP <code>"
  method=$1; path=$2; body=${3:-}
  t=$(date +%s)
  n=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  bh=$(printf '%s' "$body" | openssl dgst -sha256 | sed 's/^.*= //')
  text=$(printf '%s\n%s\n%s\n%s\n%s' "$method" "$path" "$t" "$n" "$bh")
  sig=$(printf '%s' "$text" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$(cat "$D/secret")" | sed 's/^.*= //')
  if [ -n "$body" ]; then
    curl -sS -X "$method" -H "X-BF-Time: $t" -H "X-BF-Nonce: $n" -H "X-BF-Sig: $sig" --data-binary "$body" -w '\nHTTP %{http_code}\n' "$URL$path"
  else
    curl -sS -X "$method" -H "X-BF-Time: $t" -H "X-BF-Nonce: $n" -H "X-BF-Sig: $sig" -w '\nHTTP %{http_code}\n' "$URL$path"
  fi
}

summary() { # reads the status JSON on stdin
  python3 -c '
import json, sys
s = json.load(sys.stdin)
print("online=%s total=%s desired=%s load1=%s port=%s" % (s["online"], s["peers_total"], s["desired_version"], s["load1"], s["interface"]["listen_port"]))
for p in s["peers"]:
    print("  peer %s.. online=%s age=%s endpoint=%s ips=%s" % (p["public_key"][:6], p["online"], p["handshake_age"], p["endpoint"], ",".join(p["allowed_ips"])))
'
}
status() { call GET /v1/status | head -n 1 | summary; }
peer() { printf '{"public_key":"%s","allowed_ips":["%s"]}' "$1" "$2"; }
list() { printf '{"version":%s,"peers":[%s]}' "$1" "$2"; }
short() { cut -c1-6; }

step "setup: two throwaway WireGuard interfaces (wgtest0 is managed by the agent, wgtest1 plays a client)"
k0=$(wg genkey); k1=$(wg genkey)
printf '%s' "$k0" > "$D/k0"; printf '%s' "$k1" > "$D/k1"
p0=$(printf '%s' "$k0" | wg pubkey); p1=$(printf '%s' "$k1" | wg pubkey)
p2=$(wg genkey | wg pubkey); stray=$(wg genkey | wg pubkey)
ip link add wgtest0 type wireguard
ip link add wgtest1 type wireguard
wg set wgtest0 private-key "$D/k0" listen-port 51899
wg set wgtest1 private-key "$D/k1" listen-port 51898
ip link set wgtest0 up; ip link set wgtest1 up
wg set wgtest0 peer "$stray" allowed-ips 10.99.0.50/32
echo "wgtest0 peers: $(wg show wgtest0 peers | short | tr '\n' ' ')(stray = $(printf '%s' "$stray" | short))"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$D/secret"
export BF_LISTEN=127.0.0.1:$PORT BF_INTERFACE=wgtest0 BF_SECRET_FILE="$D/secret" BF_STATE_DIR="$D/state" BF_WG_BIN=/usr/bin/wg
"$BIN" > "$D/agent.log" 2>&1 &
PID=$!
sleep 1

step "1. probe, with no list given: the stray peer must still be there (the agent leaves WireGuard alone)"
"$BIN" probe | summary
echo "wgtest0 peers: $(wg show wgtest0 peers | short | tr '\n' ' ')"

step "2. an unsigned request gets an empty 404"
curl -sS -i "$URL/v1/status" | tr -d '\r' | grep -v '^date:'

step "3. PUT version 1 = [p1]: expect added 1, removed 1 (the stray)"
call PUT /v1/peers "$(list 1 "$(peer "$p1" 10.99.0.2/32)")"
echo "wgtest0 peers: $(wg show wgtest0 peers | short | tr '\n' ' ')(p1 = $(printf '%s' "$p1" | short))"

step "4. a real handshake: wgtest1 contacts wgtest0 over loopback"
wg set wgtest1 peer "$p0" endpoint 127.0.0.1:51899 allowed-ips 10.99.0.1/32 persistent-keepalive 1
sleep 3
status
echo "real endpoint on the node, for comparison only: $(wg show wgtest0 endpoints | cut -f2)"

step "5. PUT version 1 again (a retry) = zero changes"
call PUT /v1/peers "$(list 1 "$(peer "$p1" 10.99.0.2/32)")"

step "6. PUT version 2 = [p1 unchanged, p2 new]: expect added 1; p1 must keep its endpoint (not disturbed)"
before=$(wg show wgtest0 endpoints | grep "^$p1" | cut -f2)
call PUT /v1/peers "$(list 2 "$(peer "$p1" 10.99.0.2/32),$(peer "$p2" 10.99.0.3/32)")"
after=$(wg show wgtest0 endpoints | grep "^$p1" | cut -f2)
if [ "$before" = "$after" ] && [ -n "$after" ]; then echo "p1 endpoint unchanged: OK"; else echo "p1 endpoint CHANGED: before=$before after=$after"; fi

step "7. PUT version 3 = p2 gets a new range: expect updated 1"
call PUT /v1/peers "$(list 3 "$(peer "$p1" 10.99.0.2/32),$(peer "$p2" 10.99.0.30/32)")"
wg show wgtest0 allowed-ips | sed 's/^\(......\)[^\t]*/\1../'

step "8. refused: an older version (409) and a bad key (400)"
call PUT /v1/peers "$(list 2 "$(peer "$p1" 10.99.0.2/32)")"
call PUT /v1/peers "$(list 4 "$(peer short 10.99.0.9/32)")"

step "9. restart: remove p2 behind the agent's back, restart the agent, and it must come back"
# A request is signed once and sent again unchanged, which is what a replay is.
RT=$(date +%s)
RN=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
RH=$(printf '' | openssl dgst -sha256 | sed 's/^.*= //')
RSIG=$(printf 'GET\n/v1/status\n%s\n%s\n%s' "$RT" "$RN" "$RH" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$(cat "$D/secret")" | sed 's/^.*= //')
replay() { curl -sS -H "X-BF-Time: $RT" -H "X-BF-Nonce: $RN" -H "X-BF-Sig: $RSIG" -o /dev/null -w 'HTTP %{http_code}' "$URL/v1/status"; }
echo "a signed request, sent for the first time:  $(replay) (expect 200)"
echo "the same bytes again, same process:         $(replay) (expect 404: the nonce is remembered)"
kill "$PID"; wait "$PID" 2>/dev/null || true
wg set wgtest0 peer "$p2" remove
echo "wgtest0 peers while the agent is down: $(wg show wgtest0 peers | short | tr '\n' ' ')"
"$BIN" >> "$D/agent.log" 2>&1 &
PID=$!
sleep 2
echo "wgtest0 peers after restart:           $(wg show wgtest0 peers | short | tr '\n' ' ')"
echo "the same bytes after the restart:           $(replay) (expect 404: the replay mark, the nonce is forgotten)"
echo "replay mark on disk: $(cat "$D/state/replay-mark" 2>/dev/null || echo none) (the request's time was $RT)"
status

step "10. secrets: neither the agent log nor any answer may hold the interface private key or the signing secret"
all=$( (cat "$D/agent.log"; call GET /v1/status) 2>&1 )
for secret in "$k0" "$(cat "$D/secret")"; do
  if printf '%s' "$all" | grep -qF "$secret"; then echo "LEAK of a secret"; else echo "no leak"; fi
done
echo "--- agent log ---"
cat "$D/agent.log"

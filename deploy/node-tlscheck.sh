#!/bin/sh
# Checks the TLS that Caddy puts in front of a node's agent (see deploy/deploy-caddy.sh).
# Run it ON the node, so it can read the node's root certificate and the agent's secret and
# can speak to the node's own public address. Needs curl, openssl, python3 and timeout.
#
#   ssh <ssh opts> <user@node> 'sh -s -- <node-name> <node public ip>' < deploy/node-tlscheck.sh
#   e.g. ssh -i ~/.ssh/your_key root@toronto.example.ts.net 'sh -s -- toronto 192.0.2.176' < deploy/node-tlscheck.sh
#
# Every line says PASS or FAIL. The exit code is the number of FAILs. It never changes
# anything on the node. Takes about 30 seconds, because it waits for the timeouts to fire.
set -u

NODE=${1:?usage: sh -s -- <node-name> <node public ip>}
IP=${2:?usage: sh -s -- <node-name> <node public ip>}
NAME=$NODE.agent.internal
PORT=8443
ROOT=$(find /var/lib/caddy -path '*pki/authorities/local/root.crt' 2>/dev/null | head -n 1)
SECRET=/etc/barely-free/agent.secret
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() { # description, then a command: passes when the command succeeds
  desc=$1; shift
  if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

if [ -z "$ROOT" ] || [ ! -s "$ROOT" ]; then
  fail "Caddy's local root certificate exists (looked under /var/lib/caddy)"
  printf '\n%s check(s) failed\n' "$fails"
  exit "$fails"
fi
pass "Caddy's local root certificate exists ($ROOT)"

handshake() { # sni-or-empty [extra openssl options]: one TLS handshake with the public address
  sni=$1; shift
  if [ -n "$sni" ]; then
    printf '' | timeout 10 openssl s_client -brief -connect "$IP:$PORT" -servername "$sni" "$@" 2>&1
  else
    printf '' | timeout 10 openssl s_client -brief -connect "$IP:$PORT" "$@" 2>&1
  fi
}

# --- the certificate and the protocol -------------------------------------------------
out=$(handshake "$NAME" -CAfile "$ROOT" -verify_return_error -verify_hostname "$NAME")
case $out in
  *"Verification: OK"*) pass "the node's certificate verifies against its own root, for $NAME" ;;
  *) fail "the node's certificate verifies against its own root, for $NAME" ;;
esac
case $out in
  *"Protocol version: TLSv1.3"* | *"Protocol version: TLSv1.2"*) pass "the protocol is TLS 1.2 or 1.3" ;;
  *) fail "the protocol is TLS 1.2 or 1.3" ;;
esac

out=$(handshake "$NAME" -tls1_1)
case $out in
  *"CONNECTION ESTABLISHED"*) fail "TLS 1.1 is refused" ;;
  *) pass "TLS 1.1 is refused" ;;
esac

out=$(handshake "" -CAfile "$ROOT")
case $out in
  *"CONNECTION ESTABLISHED"*) fail "a client that sends no server name gets no certificate" ;;
  *) pass "a client that sends no server name gets no certificate" ;;
esac

out=$(handshake "other.agent.internal" -CAfile "$ROOT")
case $out in
  *"CONNECTION ESTABLISHED"*) fail "a client that asks for another name gets no certificate" ;;
  *) pass "a client that asks for another name gets no certificate" ;;
esac

# --- what the agent answers through the proxy -----------------------------------------
code=$(curl -sS --max-time 10 --cacert "$ROOT" --resolve "$NAME:$PORT:$IP" -o /dev/null \
  -w '%{http_code} %{size_download}' "https://$NAME:$PORT/v1/status" </dev/null 2>&1)
if [ "$code" = "404 0" ]; then pass "an unsigned request gets the agent's empty 404"; else fail "an unsigned request gets the agent's empty 404 (got: $code)"; fi

server=$(curl -sS --max-time 10 --cacert "$ROOT" --resolve "$NAME:$PORT:$IP" -D - -o /dev/null \
  "https://$NAME:$PORT/v1/status" </dev/null 2>&1 | tr -d '\r' | grep -i '^server:' || true)
if [ -z "$server" ]; then pass "the reply does not name the web server"; else fail "the reply does not name the web server ($server)"; fi

if [ -r "$SECRET" ]; then
  t=$(date +%s)
  n=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  bh=$(printf '' | openssl dgst -sha256 | sed 's/^.*= //')
  text=$(printf '%s\n%s\n%s\n%s\n%s' GET /v1/status "$t" "$n" "$bh")
  sig=$(printf '%s' "$text" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$(cat "$SECRET")" | sed 's/^.*= //')
  body=$(curl -sS --max-time 10 --cacert "$ROOT" --resolve "$NAME:$PORT:$IP" \
    -H "X-BF-Time: $t" -H "X-BF-Nonce: $n" -H "X-BF-Sig: $sig" \
    -w '\nHTTP %{http_code}' "https://$NAME:$PORT/v1/status" </dev/null 2>&1)
  case $body in
    *'"peers_total"'*"HTTP 200") pass "a signed GET /v1/status through TLS gets the status" ;;
    *) fail "a signed GET /v1/status through TLS gets the status (got: $(printf '%s' "$body" | tail -c 120))" ;;
  esac
else
  fail "the agent's secret can be read, to sign a request ($SECRET)"
fi

# --- what is not reachable ------------------------------------------------------------
code=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "http://$IP:$PORT/v1/status" </dev/null 2>/dev/null || true)
case $code in
  200) fail "plain HTTP on port $PORT does not reach the agent (got 200)" ;;
  *) pass "plain HTTP on port $PORT does not reach the agent (got: ${code:-no answer})" ;;
esac

if curl -sS --max-time 5 -o /dev/null "http://$IP:9870/v1/status" </dev/null 2>/dev/null; then
  fail "the agent's own port 9870 is not open on the public address"
else
  pass "the agent's own port 9870 is not open on the public address"
fi

# --- slow clients are cut off ---------------------------------------------------------
slow() { # kind (header|body), seconds allowed: a client that stalls must be cut off or answered by then
  python3 - "$IP" "$PORT" "$NAME" "$ROOT" "$1" "$2" <<'PY'
import socket, ssl, sys, time
ip, port, name, root, kind, limit = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], float(sys.argv[6])
ctx = ssl.create_default_context(cafile=root)
tls = ctx.wrap_socket(socket.create_connection((ip, port), timeout=5), server_hostname=name)
host = ("Host: " + name + "\r\n").encode()
if kind == "header":
    tls.sendall(b"GET /v1/status HTTP/1.1\r\n" + host + b"X-Slow: a")  # the header block never ends
else:
    tls.sendall(b"PUT /v1/peers HTTP/1.1\r\n" + host + b"Content-Length: 100\r\n\r\nhello")  # 95 bytes never come
tls.settimeout(limit)
start = time.time()
try:
    answer = tls.recv(4096)
    how = "answered or closed"
    if answer.startswith(b"HTTP/1.1 200") or answer.startswith(b"HTTP/2 200"):
        print("got a 200"); sys.exit(1)
except socket.timeout:
    print("still open after %.0fs" % (time.time() - start)); sys.exit(1)
except (ssl.SSLError, OSError):
    how = "closed"
print("%s after %.1fs" % (how, time.time() - start))
PY
}
if result=$(slow header 8); then pass "a client that never finishes its headers is cut off ($result)"; else fail "a client that never finishes its headers is cut off ($result)"; fi
if result=$(slow body 20); then pass "a client that never finishes its body is cut off ($result)"; else fail "a client that never finishes its body is cut off ($result)"; fi

# --- the old holding page still answers -----------------------------------------------
page=$(curl -sS -k --max-time 10 --resolve "barely-free.com:443:127.0.0.1" "https://barely-free.com/" </dev/null 2>&1 || true)
case $page in
  *"being rebuilt"*) pass "the holding page on port 443 still answers" ;;
  *) fail "the holding page on port 443 still answers (got: $(printf '%s' "$page" | head -c 80))" ;;
esac

printf '\n%s check(s) failed\n' "$fails"
exit "$fails"

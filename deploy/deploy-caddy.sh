#!/bin/sh
# Puts HTTPS in front of a node's agent: Caddy listens on port 8443 with a certificate from
# its own local CA, and passes requests to the agent on 127.0.0.1:9870. The holding page on
# ports 80 and 443 is left alone.
#
#   deploy/deploy-caddy.sh <user@host> <node-name> [ssh options...]
#   deploy/deploy-caddy.sh root@<node ip> toronto -i ~/.ssh/<key> -o IdentitiesOnly=yes
#
# <node-name> becomes the certificate's name, <node-name>.agent.internal. To open port 8443
# only to the web VM instead of everyone, set BF_CONTROL_IP=<its address>. Safe to run
# again. To take it back out:  BF_UNDO=1 deploy/deploy-caddy.sh <user@host> <node-name> ...
#
# Afterwards check it:  ssh <opts> <user@host> 'sh -s -- <node-name> <node ip>' < deploy/node-tlscheck.sh
# and copy the node's root certificate (public, not a secret) as the README says.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
host=${1:?usage: deploy/deploy-caddy.sh <user@host> <node-name> [ssh options...]}
node=${2:?usage: deploy/deploy-caddy.sh <user@host> <node-name> [ssh options...]}
shift 2
case $node in
  '' | *[!a-z0-9-]* | -*) echo "the node name must be lowercase letters, digits and '-', not starting with '-'" >&2; exit 2 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sed "s/__NAME__/$node/" "$root/deploy/caddy/agent.caddy" > "$work/agent.caddy"
cp "$root/deploy/caddy/agent.global" "$work/agent.global"

scp "$@" "$work/agent.global" "$host:/etc/caddy/barely-free-agent.global.new"
scp "$@" "$work/agent.caddy" "$host:/etc/caddy/barely-free-agent.caddy.new"

# One ssh session for everything else: the nodes rate-limit new SSH connections.
ssh "$@" "$host" "BF_UNDO=${BF_UNDO:-} BF_CONTROL_IP=${BF_CONTROL_IP:-} sh -s" <<'REMOTE'
set -eu
CADDYFILE=/etc/caddy/Caddyfile
BACKUP=/etc/caddy/Caddyfile.before-bf-agent
GLOBAL=/etc/caddy/barely-free-agent.global
SITE=/etc/caddy/barely-free-agent.caddy

restore() { cp -p "$BACKUP" "$CADDYFILE"; systemctl reload caddy; }
# Validate as the caddy user, with its own home: loading `tls internal` creates the local CA
# in the caller's data directory, and that must be the service's, not root's.
validate() { runuser -u caddy -- env HOME=/var/lib/caddy caddy validate --config "$CADDYFILE" --adapter caddyfile; }

if [ -n "${BF_UNDO:-}" ]; then
  [ -f "$BACKUP" ] || { echo "no backup at $BACKUP: nothing to undo" >&2; exit 1; }
  restore
  rm -f "$GLOBAL" "$SITE" "$GLOBAL.new" "$SITE.new"
  ufw delete allow 8443/tcp >/dev/null 2>&1 || echo "no 'allow 8443/tcp' rule to delete (a source-limited one? see: ufw status numbered)"
  echo "undone: Caddyfile restored from $BACKUP"
  exit 0
fi

mv "$GLOBAL.new" "$GLOBAL"
mv "$SITE.new" "$SITE"

if ! grep -q 'barely-free-agent.global' "$CADDYFILE"; then
  [ -f "$BACKUP" ] || cp -p "$CADDYFILE" "$BACKUP"
  [ "$(head -n 1 "$CADDYFILE")" = "{" ] || { echo "the Caddyfile does not start with a global options block: not touching it" >&2; exit 1; }
  new=$(mktemp)
  awk 'NR == 1 { print; print "\timport /etc/caddy/barely-free-agent.global"; next } { print }' "$CADDYFILE" > "$new"
  printf '\n# The agent over HTTPS (deploy/deploy-caddy.sh)\nimport /etc/caddy/barely-free-agent.caddy\n' >> "$new"
  cat "$new" > "$CADDYFILE"
  rm -f "$new"
fi

if ! validate >/dev/null 2>&1; then
  validate 2>&1 | tail -5 >&2 || true
  echo "caddy rejects the new configuration: putting the original Caddyfile back" >&2
  [ -f "$BACKUP" ] && cp -p "$BACKUP" "$CADDYFILE"
  exit 1
fi

if [ -n "${BF_CONTROL_IP:-}" ]; then
  ufw allow from "$BF_CONTROL_IP" to any port 8443 proto tcp >/dev/null
  echo "ufw: port 8443 open to $BF_CONTROL_IP only"
else
  ufw allow 8443/tcp >/dev/null
  echo "ufw: port 8443 open to everyone (the agent still needs a valid signature)"
fi

systemctl reload caddy
i=0
while [ $i -lt 15 ]; do
  if ss -ltn | grep -q ':8443 '; then break; fi
  sleep 1; i=$((i + 1))
done
if ! ss -ltn | grep -q ':8443 '; then
  echo "Caddy is not listening on 8443 after 15 s: putting the original Caddyfile back" >&2
  restore
  exit 1
fi
echo "caddy: $(systemctl is-active caddy), listening on 8443"
sleep 2
echo "root certificate: $(find /var/lib/caddy -path '*pki/authorities/local/root.crt' | head -n 1)"
REMOTE

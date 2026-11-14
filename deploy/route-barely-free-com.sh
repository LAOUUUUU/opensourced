#!/bin/sh
# Run ON the web VM (as root): sends barely-free.com and www.barely-free.com to the new
# website (127.0.0.1:18500) in haproxy's tunnel door, /etc/haproxy/cf-tunnel.cfg. Every
# other name keeps going where it went. The old build's names are checked before and after,
# and the change is undone by itself if any of them answers differently.
#
#   ssh <vm> 'sh -s' < deploy/route-barely-free-com.sh            # apply
#   ssh <vm> 'sh -s -- undo' < deploy/route-barely-free-com.sh    # put the old file back
#
# This changes where the NAMES go inside the VM. Whether the world reaches them is a DNS
# matter in the other Cloudflare account (see docs/modules/bf-control.md).
set -eu

CFG=/etc/haproxy/cf-tunnel.cfg
BACKUP=/root/cf-tunnel.cfg.before-bf-control

check() { # <host> <path>: prints the HTTP status haproxy's tunnel door gives that name
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H "Host: $1" -H 'CF-Connecting-IP: 203.0.113.1' "http://127.0.0.1:14440$2" || true
}
validate() { haproxy -c -q -f /etc/haproxy/haproxy.cfg -f "$CFG"; }
OLD_NAMES='old.example.com:/ sub.old.example.com:/ status.old.example.com:/status panel.barely-free.com:/ status.barely-free.com:/status'

if [ "${1:-}" = undo ]; then
  [ -f "$BACKUP" ] || { echo "no backup at $BACKUP: nothing to undo" >&2; exit 1; }
  cp -p "$BACKUP" "$CFG" && validate && systemctl reload haproxy
  echo "restored $CFG from $BACKUP"
  exit 0
fi

before=''
for pair in $OLD_NAMES; do before="$before $(check "${pair%%:*}" "${pair#*:}")"; done
echo "old names before:$before"

[ -f "$BACKUP" ] || cp -p "$CFG" "$BACKUP"
python3 - "$CFG" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
if "be_cf_web" in text:
    print("already routed")
    raise SystemExit(0)
anchor_use = "    use_backend be_cf_panel if h_panel\n"
anchor_acl = "    http-request return status 404 if !h_panel !h_sub\n"
assert text.count(anchor_use) == 1 and text.count(anchor_acl) == 1, "cf-tunnel.cfg is not what this script expects"
text = text.replace(anchor_acl, anchor_acl +
    "    acl h_web req.hdr(host),field(1,:),lower -m str barely-free.com www.barely-free.com\n")
text = text.replace(anchor_use, "    use_backend be_cf_web if h_web\n" + anchor_use)
text = text.rstrip("\n") + "\n\nbackend be_cf_web\n    mode http\n    option http-server-close\n    server web 127.0.0.1:18500\n"
open(path, "w", encoding="utf-8").write(text)
PY

if ! validate; then echo "haproxy rejects the new file: undoing" >&2; cp -p "$BACKUP" "$CFG"; exit 1; fi
systemctl reload haproxy
sleep 1

after=''
for pair in $OLD_NAMES; do after="$after $(check "${pair%%:*}" "${pair#*:}")"; done
echo "old names after: $after"
new_front=$(curl -s --max-time 10 -H 'Host: barely-free.com' -H 'CF-Connecting-IP: 203.0.113.1' http://127.0.0.1:14440/ | grep -c '<title>Barely-free')
new_www=$(curl -s --max-time 10 -H 'Host: www.barely-free.com' -H 'CF-Connecting-IP: 203.0.113.1' http://127.0.0.1:14440/ | grep -c '<title>Barely-free')
echo "new site answers: barely-free.com=$new_front www.barely-free.com=$new_www (1 means the new front page)"

if [ "$before" != "$after" ] || [ "$new_front" != 1 ] || [ "$new_www" != 1 ]; then
  echo "something answers differently: undoing" >&2
  cp -p "$BACKUP" "$CFG" && validate && systemctl reload haproxy
  exit 1
fi
echo "routed. Undo with: sh -s -- undo < deploy/route-barely-free-com.sh"

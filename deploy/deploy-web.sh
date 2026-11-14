#!/bin/sh
# Builds bf-control (the website) for Linux on this Mac and installs it on the web VM.
#
#   deploy/deploy-web.sh <user@host> [ssh options...]
#   deploy/deploy-web.sh root@<vm ip> -o Port=<ssh port>
#
# It only listens on 127.0.0.1:18500; nothing is public until the Cloudflare tunnel points
# at it (see deploy/route-barely-free-com.sh and docs/modules/bf-control.md). Safe to run
# again to update. Use -o Port=... rather than -p, because scp and ssh read -p differently.
#
# Before the new program is in place it stops the service and copies the database to
# /var/lib/barely-free/control.db.before-deploy-<UTC time> (the newest five are kept).
#
# It also installs the nodes' public root certificates (deploy/node-roots/*.pem) into
# /etc/barely-free/nodes, where the poller pins them. A node's signing secret is not here:
# deploy/set-node-secret.sh moves it, and you run that yourself.
#
# And bf-logins.timer (deploy/bf-logins.{sh,service,timer}), which writes the VM's own SSH
# logins into /var/lib/barely-free-logins for the login alerts (specs/login-alerts.md). The
# website's user joins the group bf-logins that may read it. It runs once before the website
# restarts, so a first look that learns sees them too.
set -eu

target=x86_64-unknown-linux-musl
root=$(cd "$(dirname "$0")/.." && pwd)
host=${1:?usage: deploy/deploy-web.sh <user@host> [ssh options...]}
shift

cd "$root"
cargo zigbuild --release --target "$target" -p bf-control

scp "$@" "target/$target/release/bf-control" "$host:/usr/local/bin/bf-control.new"
# The unit arrives beside the real one and is moved into place only after the database copy
# below has worked, so a failed copy leaves the old program with its old unit.
scp "$@" deploy/bf-control.service "$host:/etc/systemd/system/bf-control.service.new"
ssh "$@" "$host" 'rm -rf /tmp/bf-node-roots /tmp/bf-logins && mkdir -m 0700 /tmp/bf-node-roots /tmp/bf-logins'
scp "$@" deploy/node-roots/*.pem "$host:/tmp/bf-node-roots/"
scp "$@" deploy/bf-logins.sh deploy/bf-logins.service deploy/bf-logins.timer "$host:/tmp/bf-logins/"

ssh "$@" "$host" 'sh -s' <<'REMOTE'
set -eu
# A copy of the database before the new program can touch it: a newer program may upgrade the
# schema (version 4 adds sessions.keep), and an older one refuses an upgraded database, so
# going back means this copy too. The service is stopped first so the copy is consistent;
# it starts again below. The newest five copies are kept.
# The copy is made by the new program's own `backup`, as the website's user: owner
# barely-free, mode 0600, read-only on the database, and without the short-lived sign-in
# records, which the privacy policy says are gone after a day (decision 016, amended). If it
# fails, the old program starts again and nothing is installed.
db=/var/lib/barely-free/control.db
chmod 755 /usr/local/bin/bf-control.new
if [ -f "$db" ]; then
  systemctl stop bf-control.service
  copy="$db.before-deploy-$(date -u +%Y%m%dT%H%M%SZ)"
  if ! runuser -u barely-free -- env BC_DB="$db" /usr/local/bin/bf-control.new backup "$copy"; then
    echo "the copy of the database failed: the old program is started again and nothing is installed" >&2
    rm -f /etc/systemd/system/bf-control.service.new
    systemctl start bf-control.service
    exit 1
  fi
  echo "database copied to $copy"
  # The names end in a UTC time, so the glob lists them oldest first.
  set -- "$db".before-deploy-*
  while [ "$#" -gt 5 ]; do rm -f -- "$1"; shift; done
fi
mv /etc/systemd/system/bf-control.service.new /etc/systemd/system/bf-control.service
mv /usr/local/bin/bf-control.new /usr/local/bin/bf-control
if ! getent passwd barely-free >/dev/null 2>&1; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin barely-free
fi
install -d -o barely-free -g barely-free -m 0700 /var/lib/barely-free
# Made here if it is not there yet (set-resend-key.sh makes it too): under `set -eu` a missing
# folder would stop the deploy after the new program is in place but before the restart.
install -d -o root -g barely-free -m 0750 /etc/barely-free
install -d -o root -g barely-free -m 0750 /etc/barely-free/nodes
install -o root -g root -m 0644 /tmp/bf-node-roots/*.pem /etc/barely-free/nodes/
rm -rf /tmp/bf-node-roots
if [ -f /etc/barely-free/control.key ]; then chown barely-free:barely-free /etc/barely-free/control.key; fi
if [ -f /etc/barely-free/resend.key ]; then chown barely-free:barely-free /etc/barely-free/resend.key; fi
# The login alerts' timer, and the group that may read what it writes (the website joins it;
# systemd gives a service its user's groups when it starts).
getent group bf-logins >/dev/null 2>&1 || groupadd --system bf-logins
usermod -a -G bf-logins barely-free
install -d -o root -g root -m 0755 /usr/local/lib/barely-free
install -o root -g root -m 0755 /tmp/bf-logins/bf-logins.sh /usr/local/lib/barely-free/
install -o root -g root -m 0644 /tmp/bf-logins/bf-logins.service /tmp/bf-logins/bf-logins.timer /etc/systemd/system/
rm -rf /tmp/bf-logins
systemctl daemon-reload
# The VM's own logins are written once now, so the website's first look sees them. A failure
# here must not stop the deploy before the website restarts: it is said, and the website
# logs the stale file itself.
systemctl start bf-logins.service ||
  echo "bf-logins did not run (see journalctl -u bf-logins); the website starts without the VM's own logins" >&2
systemctl enable --now bf-logins.timer >/dev/null 2>&1 ||
  echo "bf-logins.timer could not be started" >&2
systemctl enable bf-control.service >/dev/null 2>&1
systemctl restart bf-control.service
sleep 1
echo "service: $(systemctl is-active bf-control.service)"
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18500/healthz)
echo "GET /healthz on localhost: HTTP $code"
[ "$code" = 200 ]
REMOTE

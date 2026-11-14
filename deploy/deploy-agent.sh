#!/bin/sh
# Builds bf-agent for Linux on this Mac and installs it on one node.
#
#   deploy/deploy-agent.sh <user@host> [ssh options...]
#   deploy/deploy-agent.sh root@<node ip> -i ~/.ssh/<key> -o IdentitiesOnly=yes
#
# First run on a node creates /etc/barely-free/agent.secret there. The secret is made on
# the node and never leaves it. The agent changes nothing in WireGuard until the control
# program sends it a peer list. Needs rustup's x86_64-unknown-linux-musl target, zig and
# cargo-zigbuild (see README.md).
#
# It also installs bf-logins.timer (deploy/bf-logins.{sh,service,timer}), which writes the
# server's recent SSH logins into /var/lib/barely-free-logins as root, and puts every agent
# in the group bf-logins that may read it (a drop-in, bf-agent*.service.d/logins.conf), so
# the status carries them for the login alerts (specs/login-alerts.md).
set -eu

target=x86_64-unknown-linux-musl
root=$(cd "$(dirname "$0")/.." && pwd)
host=${1:?usage: deploy/deploy-agent.sh <user@host> [ssh options...]}
shift

cd "$root"
cargo zigbuild --release --target "$target" -p bf-agent

# Three SSH connections in all: the nodes' ufw lets one address open 6 in 30 s, so a deploy
# right after another login still fits (pinned by tests/logins_script.rs).
scp "$@" "target/$target/release/bf-agent" "$host:/usr/local/bin/bf-agent.new"
# The unit and the login timer's files in one connection: a plain tar (no macOS extras),
# unpacked as root's own files into a fresh private folder.
COPYFILE_DISABLE=1 tar --format ustar -C deploy -cf - \
  bf-agent.service bf-logins.sh bf-logins.service bf-logins.timer |
  ssh "$@" "$host" 'rm -rf /tmp/bf-logins && mkdir -m 0700 /tmp/bf-logins &&
    tar --no-same-owner -C /tmp/bf-logins -xf - &&
    mv /tmp/bf-logins/bf-agent.service /etc/systemd/system/bf-agent.service.new'

# One ssh session for everything else: the nodes rate-limit new SSH connections.
ssh "$@" "$host" 'sh -s' <<'REMOTE'
set -eu
install -d -m 0750 /etc/barely-free
if [ ! -s /etc/barely-free/agent.secret ]; then
  (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/barely-free/agent.secret)
  echo "created /etc/barely-free/agent.secret"
fi
chmod 600 /etc/barely-free/agent.secret
chmod 755 /usr/local/bin/bf-agent.new
mv /usr/local/bin/bf-agent.new /usr/local/bin/bf-agent
# The repo's unit drives wg0. A server whose first agent drives another interface (Toronto:
# awg0, with /usr/bin/awg) keeps it: the new unit gets that server's interface settings.
unit=/etc/systemd/system/bf-agent.service
if [ -f "$unit" ]; then
  dev=$(sed -n 's/^Environment=BF_INTERFACE=//p' "$unit")
  bin=$(sed -n 's/^Environment=BF_WG_BIN=//p' "$unit")
  if [ -n "$dev" ] && [ "$dev" != wg0 ]; then
    case $dev in awg*) quick=awg-quick ;; *) quick=wg-quick ;; esac
    sed -e "s#^Environment=BF_INTERFACE=wg0\$#Environment=BF_INTERFACE=$dev#" \
      -e "s#^Environment=BF_WG_BIN=/usr/bin/wg\$#Environment=BF_WG_BIN=$bin#" \
      -e "s#wg-quick@wg0#$quick@$dev#g" "$unit.new" > "$unit.merged"
    mv "$unit.merged" "$unit.new"
    echo "kept this server's interface: $dev ($bin)"
  fi
fi
mv "$unit.new" "$unit"
# The login alerts: the timer writes, the group reads. The group must exist before an agent
# that names it starts, or the agent would not start.
getent group bf-logins >/dev/null 2>&1 || groupadd --system bf-logins
install -d -m 0755 /usr/local/lib/barely-free
install -m 0755 /tmp/bf-logins/bf-logins.sh /usr/local/lib/barely-free/
install -m 0644 /tmp/bf-logins/bf-logins.service /tmp/bf-logins/bf-logins.timer /etc/systemd/system/
rm -rf /tmp/bf-logins
for agent in /etc/systemd/system/bf-agent.service /etc/systemd/system/bf-agent-*.service; do
  [ -e "$agent" ] || continue
  install -d -m 0755 "$agent.d"
  printf '[Service]\nSupplementaryGroups=bf-logins\n' > "$agent.d/logins.conf"
  chmod 644 "$agent.d/logins.conf"
done
systemctl daemon-reload
# Written once now, so the restarted agents report straight away. A failure must not stop
# the deploy before the agents restart: it is said, and the agents log the missing file.
systemctl start bf-logins.service ||
  echo "bf-logins did not run (see journalctl -u bf-logins); the agents report no logins until it does" >&2
systemctl enable --now bf-logins.timer >/dev/null 2>&1 ||
  echo "bf-logins.timer could not be started" >&2
systemctl enable bf-agent.service >/dev/null 2>&1
systemctl restart bf-agent.service
# A server with both protocols has a second agent (deploy/node-add-protocol.sh): same binary.
for second in /etc/systemd/system/bf-agent-*.service; do
  [ -e "$second" ] || continue
  systemctl restart "$(basename "$second")"
  echo "$(basename "$second"): $(systemctl is-active "$(basename "$second")")"
done
sleep 1
echo "service: $(systemctl is-active bf-agent.service)"
# With no replay mark yet (the first start of a build that keeps one) the agent refuses
# requests signed in the second it started, and on a busy node that can be the second the
# probe is signed in. Try again for up to 10 s before reporting the real answer.
i=0
until /usr/local/bin/bf-agent probe >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -lt 10 ] || break
  sleep 1
done
/usr/local/bin/bf-agent probe
REMOTE

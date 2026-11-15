#!/bin/sh
# A node's small, reversible tuning (decision 029). One SSH connection; nobody is disconnected.
#
#   1. /etc/sysctl.d/99-vpn.conf = deploy/node-sysctl.conf (forwarding, BBR with fq, 7.5 MB
#      socket buffers, a longer input queue, MTU probing: written by hand on Dallas and Toronto
#      before 2026-11-15 and kept here byte for byte; then a connection-tracking table of
#      65,536 entries instead of 8,192). nf_conntrack is loaded first, now and at every boot
#      (/etc/modules-load.d/bf-conntrack.conf, read before the sysctl files), so its settings
#      exist when the file is applied. Applied with `sysctl -p` only when the file differs.
#   2. ethtool from Debian, and UDP GRO forwarding on the interface that reaches the internet
#      (`ethtool -K <wan> rx-udp-gro-forwarding on rx-gro-list off`, as Tailscale recommends
#      for Linux machines that forward traffic), now and at every boot through
#      /etc/systemd/system/bf-udp-gro.service. Left out, with a line saying so, where the
#      kernel shows the feature as [fixed].
#   3. `ufw logging off`: the rules stay; the kernel stops logging every internet scan
#      ([UFW BLOCK], about 4,300 lines a day). fail2ban reads sshd's log, not ufw's.
#   4. The clock's zone: Etc/UTC (it was Asia/Kolkata). `OnCalendar=daily` timers then fire at
#      00:00 UTC instead of 18:30 UTC; logs and `last` show UTC.
# What was there before (the zone, ufw's log level) is noted once in
# /etc/barely-free/node-tune.before, and a different sysctl file is kept as
# 99-vpn.conf.before-node-tune.
#
# The live changes (sysctl, ethtool) come first: if one fails, no file has been written and
# nothing else has changed. Safe to run again: it changes only what differs. It refuses to
# run where ufw is not active. At the end it checks that every value in force matches the
# file, shows the GRO setting, the zone and every timer, and exits 1 on a mismatch.
#
# Run it yourself, once per node:
#   deploy/node-tune.sh root@<node>.example.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes
#
# The way back, on a node, step by step:
#   1. sysctl: put 99-vpn.conf.before-node-tune back (the servers' own file from before the
#      conntrack lines), `sysctl --system`, then `sysctl -w net.netfilter.nf_conntrack_max=8192
#      net.netfilter.nf_conntrack_buckets=8192` (or reboot); remove bf-conntrack.conf.
#   2. GRO: `systemctl disable --now bf-udp-gro.service`, remove the unit, `systemctl
#      daemon-reload`, `ethtool -K <wan> rx-udp-gro-forwarding off` (the kernel's default);
#      `apt-get purge ethtool` if wanted.
#   3. ufw: `ufw logging low` (the level noted in node-tune.before).
#   4. Clock: `timedatectl set-timezone Asia/Kolkata` (the zone noted in node-tune.before).
set -eu

host=${1:?usage: deploy/node-tune.sh <user@host> [ssh options...]}
shift
sysctl_conf="$(dirname "$0")/node-sysctl.conf"
[ -f "$sysctl_conf" ] || { echo "$sysctl_conf is not there; nothing was changed" >&2; exit 1; }
! grep -qx 'BF_SYSCTL_END' "$sysctl_conf" || { echo "$sysctl_conf holds the end marker" >&2; exit 1; }

{
  # The repository's sysctl file goes first, into a file on the node the script reads.
  printf '%s\n' 'set -eu' 'umask 022' 'tmp=$(mktemp -d)' "trap 'rm -rf \"\$tmp\"' EXIT" \
    "cat > \"\$tmp/99-vpn.conf\" <<'BF_SYSCTL_END'"
  cat "$sysctl_conf"
  printf '%s\n' 'BF_SYSCTL_END'
  cat <<'REMOTE'
say() { printf '%s\n' "$*"; }
fail() { printf '%s\n' "$*" >&2; exit 1; }

# 0. Checks; nothing changes until they pass.
[ "$(id -u)" = 0 ] || fail "run this as root on the node; nothing was changed"
ufw=$(ufw status verbose) || fail "ufw status failed; nothing was changed"
printf '%s\n' "$ufw" | grep -q '^Status: active' \
  || fail "ufw is not active here: tune a node only behind its firewall; nothing was changed"
# "Logging: on (low)" -> low; "Logging: off" -> off.
ufw_level=$(printf '%s\n' "$ufw" | sed -n 's/^Logging: on (\(.*\))$/\1/p; s/^Logging: off$/off/p')
[ -n "$ufw_level" ] || fail "cannot read ufw's log level; nothing was changed"
zone=$(timedatectl show -p Timezone --value) || fail "cannot read the clock's zone; nothing was changed"
wan=$(ip -o route get 1.1.1.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p')
[ -n "$wan" ] || fail "cannot tell which interface reaches the internet; nothing was changed"

# put FILE MODE < content: writes FILE only when the content differs. True if it wrote.
put() {
  mkdir -p "$(dirname "$1")" || fail "cannot make the folder of $1"
  new="$1.new.$$"
  cat > "$new" || fail "cannot write $new"
  chmod "$2" "$new" || fail "cannot set the mode of $new"
  if [ -f "$1" ] && cmp -s "$new" "$1"; then
    rm -f "$new"
    say "unchanged: $1"
    return 1
  fi
  mv "$new" "$1" || fail "cannot put $1 in place"
  say "wrote:     $1"
}

# 1. ethtool, from Debian.
if ! dpkg -s ethtool >/dev/null 2>&1; then
  apt-get update -q </dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q ethtool </dev/null
fi
ethtool=$(command -v ethtool) || fail "no ethtool after installing it; nothing was changed"

# 2. The live changes, which prove the exact commands work here. A failure stops here.
sysfile=/etc/sysctl.d/99-vpn.conf
if [ -f "$sysfile" ] && cmp -s "$tmp/99-vpn.conf" "$sysfile"; then
  sysctl_new=
else
  # Its settings (net.netfilter.*) exist only once the module is loaded.
  modprobe nf_conntrack || fail "cannot load nf_conntrack; nothing was changed"
  sysctl -p "$tmp/99-vpn.conf" >/dev/null || fail "sysctl refuses the file; nothing was changed"
  sysctl_new=1
fi
feature() { "$ethtool" -k "$wan" | sed -n "s/^$1: //p"; }
gro=$(feature rx-udp-gro-forwarding)
case $gro in
  '') gro=skip; say "gro:       $wan has no rx-udp-gro-forwarding here: left out" ;;
  *'[fixed]'*) gro=skip; say "gro:       rx-udp-gro-forwarding is fixed ($gro) on $wan: left out" ;;
  *)
    if [ "$gro" != on ] || [ "$(feature rx-gro-list)" != off ]; then
      "$ethtool" -K "$wan" rx-udp-gro-forwarding on rx-gro-list off \
        || fail "ethtool cannot turn on UDP GRO forwarding on $wan; no file was changed"
    fi
    gro=on
    ;;
esac

# 3. The files. First a note of what was there before, kept from the first run.
note=/etc/barely-free/node-tune.before
if [ ! -e "$note" ]; then
  put "$note" 644 <<EOF || true
# Written by deploy/node-tune.sh before its first change; the way back is in its header.
timezone=$zone
ufw-logging=$ufw_level
EOF
fi
if [ -n "$sysctl_new" ]; then
  if [ -f "$sysfile" ] && [ ! -e "$sysfile.before-node-tune" ]; then
    cp -p "$sysfile" "$sysfile.before-node-tune" || fail "cannot keep a copy of $sysfile"
  fi
  put "$sysfile" 644 < "$tmp/99-vpn.conf" || true
else
  say "unchanged: $sysfile"
fi
# Loaded at boot before systemd-sysctl reads the file, or the conntrack lines would be skipped.
put /etc/modules-load.d/bf-conntrack.conf 644 <<'EOF' || true
# Written by deploy/node-tune.sh (decision 029): loaded before /etc/sysctl.d is applied, so
# net.netfilter.nf_conntrack_* in 99-vpn.conf exist at boot.
nf_conntrack
EOF
if [ "$gro" = on ]; then
  unit=/etc/systemd/system/bf-udp-gro.service
  if put "$unit" 644 <<EOF; then systemctl daemon-reload; fi
# Written by deploy/node-tune.sh (decision 029): UDP GRO forwarding on $wan at every boot.
[Unit]
Description=Barely-free: UDP GRO forwarding on $wan
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$ethtool -K $wan rx-udp-gro-forwarding on rx-gro-list off

[Install]
WantedBy=multi-user.target
EOF
  systemctl is-enabled --quiet bf-udp-gro.service \
    || systemctl enable --now bf-udp-gro.service >/dev/null 2>&1 \
    || fail "cannot enable bf-udp-gro.service"
fi

# 4. ufw's logging and the clock.
if [ "$ufw_level" != off ]; then
  ufw logging off >/dev/null || fail "ufw logging off failed"
  say "ufw:       logging off (was $ufw_level)"
else
  say "ufw:       logging already off"
fi
if [ "$zone" != Etc/UTC ]; then
  timedatectl set-timezone Etc/UTC || fail "cannot set the clock to UTC"
  say "clock:     Etc/UTC (was $zone)"
else
  say "clock:     already Etc/UTC"
fi

# 5. The checks.
broken=
mismatch=
for key in $(sed -n 's/^[[:space:]]*\([a-z0-9_.-]*\)[[:space:]]*=.*/\1/p' "$sysfile"); do
  want=$(sed -n "s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p" "$sysfile" | tail -n 1 | tr -s ' \t' ' ')
  have=$(sysctl -n "$key" | tr -s ' \t' ' ')
  if [ "$have" != "$want" ]; then
    say "sysctl:    $key is $have here, the file says $want"
    mismatch=1
  fi
done
if [ -n "$mismatch" ]; then broken=1; else say "sysctl:    every value in force matches $sysfile"; fi
if [ "$gro" = on ]; then
  say "gro:       $wan rx-udp-gro-forwarding $(feature rx-udp-gro-forwarding), rx-gro-list $(feature rx-gro-list)"
fi
say "clock:     $(timedatectl show -p Timezone --value)"
say "timers (times now in UTC):"
systemctl list-timers --all --no-pager || true
[ -z "$broken" ] || exit 1
REMOTE
} | ssh "$@" "$host" 'sh -s'

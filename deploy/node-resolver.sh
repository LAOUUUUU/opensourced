#!/bin/sh
# Sets up tracker blocking on a node (specs/trackers.md).
#
# Devices send DNS to their server's in-tunnel address: 10.77.0.1 on AmneziaWG (awg0) and
# 10.78.0.1 on WireGuard (wg0). This installs unbound from Debian and makes it answer there:
#   - port 53 blocks the tracker list (EasyPrivacy, read strictly by `bf-agent trackers build`);
#   - port 5300 does not.
# A device whose owner switched blocking off is sent from 53 to 5300 of the same address by
# an nftables rule (a dnat to the named address: `redirect` would pick the interface's first
# address, which on Dallas's wg0 was an old 10.66 one). Its address sits in a set (off_awg0 or
# off_wg0) that the server's agents keep in step with the website. Nothing about queries is logged. unbound forwards to Quad9's threat-blocking resolver over TLS (decision 022), so names known to
# spread malware are refused on both ports, whatever a device's tracker switch says.
# An answer whose time ran out is still given (RFC 8767 serve-expired) when a fresh lookup
# takes over 1.8 s or fails, for at most an hour (decision 029).
#
# What it writes on the node:
#   /etc/unbound/unbound.conf.d/barely-free.conf   the listeners, tags, forwarding and zone
#   /var/lib/unbound/barely-free-trackers.rpz      the list (an empty one until the first fetch)
#   /etc/barely-free/trackers-allow.txt            names never to block (yours once it exists)
#   /usr/local/sbin/bf-trackers-update             fetch, build, reload; daily by
#   /etc/systemd/system/bf-trackers-update.{service,timer}
#   /etc/barely-free/dns-redirect.nft              the table and the two redirect rules, loaded
#   /etc/systemd/system/bf-dns-redirect.service    now and at every boot, before the agents
#   /etc/systemd/system/bf-agent*.service.d/trackers.conf   BF_TRACKERS=nft for every agent
# and it opens 53 and 5300 (UDP and TCP) in ufw, only on awg0 and wg0, only to the server's
# own in-tunnel address. It refuses to run where ufw is not active. Debian's nftables.service stays disabled: its file flushes every
# rule, ufw's included.
#
# Safe to run again: it writes only what differs, and restarts only what it changed. Run it
# again after adding an agent to a server (deploy/node-add-protocol.sh), so the new agent gets
# the switch too. A configuration unbound refuses, or will not start with, is taken back. At
# the end it finds a listed name that exists (asking localhost, which blocks nothing) and asks
# each in-tunnel address that is up whether it resolves, blocks that name on 53 and not on
# 5300; any wrong answer exits 1.
#
# Run it yourself, once per node, after the agent that knows `trackers build` is deployed:
#   deploy/node-resolver.sh root@<node ip> -i ~/.ssh/<key> -o IdentitiesOnly=yes
#
# Devices made before this keep DNS = 1.1.1.1 in their files and are not filtered until they
# are made again. To undo: remove the drop-ins and restart the agents, disable
# bf-dns-redirect.service and bf-trackers-update.timer, `nft delete table inet
# barely_free_dns`, remove barely-free.conf and restart unbound (or purge unbound).
set -eu

host=${1:?usage: deploy/node-resolver.sh <user@host> [ssh options...]}
shift

ssh "$@" "$host" 'sh -s' <<'REMOTE'
set -eu
umask 022

say() { printf '%s\n' "$*"; }
fail() { printf '%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run this as root on the node; nothing was changed"
agent=/usr/local/bin/bf-agent
if ! "$agent" trackers 2>&1 | grep -q 'trackers build'; then
  fail "$agent cannot build the tracker list yet: deploy the new agent first (deploy/deploy-agent.sh); nothing was changed"
fi
command -v nft >/dev/null 2>&1 || fail "no nft here (Debian's nftables package); nothing was changed"
ufw status | grep -q '^Status: active' \
  || fail "ufw is not active here: the resolver would answer anyone who reaches the tunnel addresses; nothing was changed"

# put FILE MODE < content: writes FILE only when the content differs. True if it wrote.
# Every step checks itself: `set -e` is off inside a function called from if, && or ||.
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

# 1. unbound, and dig for the checks below.
if ! dpkg -s unbound >/dev/null 2>&1 || ! dpkg -s bind9-dnsutils >/dev/null 2>&1; then
  apt-get update -q </dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q unbound bind9-dnsutils </dev/null
fi

# 2. The list's files. A zone with no names until the first fetch, so unbound always has one.
zone=/var/lib/unbound/barely-free-trackers.rpz
if [ ! -s "$zone" ]; then
  # shellcheck disable=SC2016 # $TTL is the zone file's own keyword, not a variable.
  printf '%s\n' '$TTL 3600' '@ SOA localhost. nobody.invalid. 1 3600 600 86400 3600' '@ NS localhost.' \
    | put "$zone" 644 || true
fi
allow=/etc/barely-free/trackers-allow.txt
if [ ! -e "$allow" ]; then
  put "$allow" 644 <<'EOF' || true
# Names the tracker list must never block, one per line. A name also frees every name under
# it, and any listed name above it. Read on the next daily update; to apply one at once:
#   systemctl start bf-trackers-update.service
EOF
fi
put /usr/local/sbin/bf-trackers-update 755 <<'EOF' || true
#!/bin/sh
# Written by deploy/node-resolver.sh: fetches EasyPrivacy, turns it into the resolver's zone
# (bf-agent refuses a list under 1,000 names or under half the one in force, and keeps that
# one), then reloads only that zone. If unbound refuses the new zone, the one before it is
# put back and reloaded, so a bad zone never waits on disk for the next start.
set -eu
zone=/var/lib/unbound/barely-free-trackers.rpz
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl --fail --silent --show-error --location --proto =https --proto-redir =https \
  --max-time 120 --max-filesize 20000000 \
  --output "$tmp/easyprivacy.txt" https://easylist.to/easylist/easyprivacy.txt
if [ -f "$zone" ]; then cp "$zone" "$tmp/previous.rpz"; fi
/usr/local/bin/bf-agent trackers build "$tmp/easyprivacy.txt" /etc/barely-free/trackers-allow.txt "$zone"
chown unbound:unbound "$zone"
if ! unbound-control auth_zone_reload trackers.rpz.barely-free; then
  if [ -f "$tmp/previous.rpz" ]; then
    cp "$tmp/previous.rpz" "$zone.restore"
    chown unbound:unbound "$zone.restore"
    mv "$zone.restore" "$zone"
    unbound-control auth_zone_reload trackers.rpz.barely-free || true
  fi
  echo "unbound refused the new list; the previous one is back" >&2
  exit 1
fi
EOF
units_changed=
put /etc/systemd/system/bf-trackers-update.service 644 <<'EOF' && units_changed=1
[Unit]
Description=Barely-free: refresh the tracker list
Wants=network-online.target
After=network-online.target unbound.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/bf-trackers-update
ProtectSystem=strict
ReadWritePaths=/var/lib/unbound
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallFilter=@system-service
SystemCallArchitectures=native
EOF
put /etc/systemd/system/bf-trackers-update.timer 644 <<'EOF' && units_changed=1
[Unit]
Description=Barely-free: refresh the tracker list every day

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
if [ -n "$units_changed" ]; then systemctl daemon-reload; fi

# 3. The resolver. Debian's package normally has remote-control on already (for
# unbound-control); if not, this file turns it on.
control=
for f in /etc/unbound/unbound.conf /etc/unbound/unbound.conf.d/*.conf; do
  case $f in */barely-free.conf) continue ;; esac
  if grep -qs '^[[:space:]]*control-enable:[[:space:]]*yes' "$f"; then control=1; fi
done
conf=/etc/unbound/unbound.conf.d/barely-free.conf
{
  cat <<'EOF'
# Written by deploy/node-resolver.sh (specs/trackers.md); a new run replaces it.
# Port 53 of each in-tunnel address blocks the tracker list, port 5300 does not.
server:
    interface: 127.0.0.1
    interface: ::1
    interface: 10.77.0.1@53
    interface: 10.77.0.1@5300
    interface: 10.78.0.1@53
    interface: 10.78.0.1@5300
    ip-freebind: yes
    interface-action: 10.77.0.1@53 allow
    interface-action: 10.77.0.1@5300 allow
    interface-action: 10.78.0.1@53 allow
    interface-action: 10.78.0.1@5300 allow
    define-tag: "trackers"
    interface-tag: 10.77.0.1@53 "trackers"
    interface-tag: 10.78.0.1@53 "trackers"
    module-config: "respip validator iterator"
    verbosity: 1
    log-queries: no
    log-replies: no
    log-local-actions: no
    log-servfail: no
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    prefetch: yes
    # RFC 8767 (decision 029): an expired name is fetched first; the stale answer (with a
    # 30 s TTL) is used only if that takes over 1.8 s or fails, and never once an hour old: a
    # longer window would keep a name Quad9 has just started blocking alive (decision 022).
    serve-expired: yes
    serve-expired-ttl: 3600
    serve-expired-client-timeout: 1800
    num-threads: 1
    msg-cache-size: 16m
    rrset-cache-size: 32m
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net

rpz:
    name: trackers.rpz.barely-free
    zonefile: /var/lib/unbound/barely-free-trackers.rpz
    tags: "trackers"
    rpz-log: no
EOF
  if [ -z "$control" ]; then
    printf '\n%s\n' 'remote-control:'
    printf '%s\n' '    control-enable: yes' '    control-interface: /run/unbound.ctl'
  fi
} > "$conf.next"
take_back() {
  if [ -f "$conf.previous" ]; then mv "$conf.previous" "$conf"; else rm -f "$conf"; fi
}
if [ -f "$conf" ]; then cp "$conf" "$conf.previous"; fi
if put "$conf" 644 < "$conf.next"; then
  rm -f "$conf.next"
  if ! unbound-checkconf >/dev/null; then
    take_back
    fail "unbound-checkconf refuses the new $conf; the old one is back and nothing was restarted"
  fi
  if ! systemctl restart unbound; then
    take_back
    systemctl restart unbound || true
    fail "unbound would not start with the new $conf; the old one is back"
  fi
  rm -f "$conf.previous"
else
  rm -f "$conf.next" "$conf.previous"
  systemctl is-active --quiet unbound || systemctl restart unbound
fi
systemctl enable unbound >/dev/null 2>&1 || true

# 4. The first list, once, if the zone has no names yet (a failed fetch leaves the empty zone).
if ! grep -q ' CNAME \.$' "$zone"; then
  systemctl start bf-trackers-update.service \
    || say "the first fetch of the list failed: unbound runs with an empty list until the daily update"
fi

# 5. The redirect for switched-off devices. Loading the file again adds what is missing and
# replaces the rules; it never empties a set, which the agents own.
nftfile=/etc/barely-free/dns-redirect.nft
cat > "$nftfile.next" <<'EOF' || fail "cannot write $nftfile.next"
#!/usr/sbin/nft -f
# Written by deploy/node-resolver.sh (specs/trackers.md). The agents fill the sets.
table inet barely_free_dns {
    set off_awg0 { type ipv4_addr; }
    set off_wg0 { type ipv4_addr; }
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
    }
}
flush chain inet barely_free_dns prerouting
table inet barely_free_dns {
    chain prerouting {
        iifname "awg0" ip daddr 10.77.0.1 ip saddr @off_awg0 udp dport 53 dnat ip to 10.77.0.1:5300
        iifname "awg0" ip daddr 10.77.0.1 ip saddr @off_awg0 tcp dport 53 dnat ip to 10.77.0.1:5300
        iifname "wg0" ip daddr 10.78.0.1 ip saddr @off_wg0 udp dport 53 dnat ip to 10.78.0.1:5300
        iifname "wg0" ip daddr 10.78.0.1 ip saddr @off_wg0 tcp dport 53 dnat ip to 10.78.0.1:5300
    }
}
EOF
if ! nft -c -f "$nftfile.next"; then
  rm -f "$nftfile.next"
  fail "nft refuses the redirect table; nothing about it was changed"
fi
put "$nftfile" 644 < "$nftfile.next" || true
rm -f "$nftfile.next"
nft -f "$nftfile"
put /etc/systemd/system/bf-dns-redirect.service 644 <<'EOF' && units_changed=1
[Unit]
Description=Barely-free: send switched-off devices' DNS to the unfiltered port
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target bf-agent.service bf-agent-wireguard.service bf-agent-amneziawg.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/barely-free/dns-redirect.nft

[Install]
WantedBy=multi-user.target
EOF

# 6. The firewall: only the VPN interfaces, only the server's own in-tunnel address.
for pair in awg0:10.77.0.1 wg0:10.78.0.1; do
  dev=${pair%%:*}
  address=${pair#*:}
  for port in 53 5300; do
    for proto in udp tcp; do
      ufw allow in on "$dev" to "$address" port "$port" proto "$proto" >/dev/null
    done
  done
done
say "ufw:       53 and 5300 open on awg0 and wg0"

# 7. The switch in every agent on this server.
restart=
for unit in /etc/systemd/system/bf-agent*.service; do
  [ -f "$unit" ] || continue
  name=$(basename "$unit")
  if put "$unit.d/trackers.conf" 644 <<'EOF'; then
# Written by deploy/node-resolver.sh: the per-device tracker switch (specs/trackers.md).
[Unit]
Wants=bf-dns-redirect.service
After=bf-dns-redirect.service

[Service]
Environment=BF_TRACKERS=nft
Environment=BF_NFT_BIN=/usr/sbin/nft
EOF
    units_changed=1
    restart="$restart $name"
  fi
done
if [ -n "$units_changed" ]; then systemctl daemon-reload; fi
systemctl enable bf-dns-redirect.service >/dev/null || fail "cannot enable bf-dns-redirect.service"
systemctl enable --now bf-trackers-update.timer >/dev/null || fail "cannot enable bf-trackers-update.timer"
for name in $restart; do
  systemctl restart "$name"
  say "restarted: $name"
done

# 8. The checks. First a listed name that exists upstream, found through localhost, which
# blocks nothing (many listed trackers are long dead, and a dead one says nothing). Then each
# in-tunnel address that is up must resolve a name, block that one on 53 and not on 5300.
status() { dig +time=3 +tries=2 "$@" A | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -n 1; }
broken=
live=
listed=$(sed -n 's/^\([a-z0-9][a-z0-9.-]*\) CNAME \.$/\1/p' "$zone")
step=$(( $(printf '%s\n' "$listed" | wc -l) / 40 + 1 ))
for name in $(printf '%s\n' "$listed" | awk -v step="$step" '(NR - 1) % step == 0' | head -n 40); do
  if [ "$(status @127.0.0.1 "$name")" = NOERROR ]; then
    live=$name
    break
  fi
done
for address in 10.77.0.1 10.78.0.1; do
  ip -4 -o addr show | grep -q "inet $address/" || continue
  if [ -z "$(dig +short +time=3 +tries=2 "@$address" example.com A)" ]; then
    say "$address: does not resolve example.com"
    broken=1
    continue
  fi
  if [ -z "$live" ]; then
    say "$address: resolves; found no listed name that exists upstream, so blocking was not checked"
    continue
  fi
  on53=$(status "@$address" "$live")
  on5300=$(status -p 5300 "@$address" "$live")
  if [ "$on5300" != NOERROR ]; then
    say "$address: port 5300 blocks $live too ($on5300): the ports share the tag (decision 015 has the fallback)"
    broken=1
  elif [ "$on53" != NXDOMAIN ]; then
    say "$address: port 53 does not block $live ($on53)"
    broken=1
  else
    say "$address: resolves, blocks $live on 53, not on 5300"
  fi
done
[ -z "$broken" ] || exit 1
REMOTE

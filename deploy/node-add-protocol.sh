#!/bin/sh
# Adds the second protocol to a server, so it offers both WireGuard and AmneziaWG
# (specs/dual-protocol.md):
#   wireguard  -> wg0  on 10.78.0.1/16, UDP 51820 (Toronto: its old wg0 is replaced)
#   amneziawg  -> awg0 on 10.77.0.1/16, UDP 443, the AmneziaWG kernel module (Dallas)
# and a second node agent for that interface (bf-agent-<protocol>.service on 127.0.0.1:9871,
# its own secret and state), reached through Caddy as <agent-name>.agent.internal:8443.
#
# Run it yourself, once per server:
#   deploy/node-add-protocol.sh root@toronto.example.ts.net wireguard toronto-wg -i ~/.ssh/your_key -o IdentitiesOnly=yes
#   deploy/node-add-protocol.sh root@dallas.example.ts.net amneziawg dallas-awg -i ~/.ssh/your_key -o IdentitiesOnly=yes
# On Dallas, run deploy/node-wireguard-range.sh first: AmneziaWG takes 10.77, which Dallas's
# wg0 holds until then.
#
# Safe to run again: each step is skipped when it is already done. Nobody already connected
# is disconnected: the server's other interface and agent are not touched. Every file it
# replaces is kept as <file>.before-dual.
set -eu

usage="usage: deploy/node-add-protocol.sh <user@host> <wireguard|amneziawg> <agent-name> [ssh options...]"
host=${1:?$usage}
protocol=${2:?$usage}
agent=${3:?$usage}
shift 3
case $protocol in
  wireguard | amneziawg) ;;
  *) echo "the protocol is wireguard or amneziawg" >&2; echo "$usage" >&2; exit 2 ;;
esac
# The same rule as bf-control's node names: a letter, then letters, digits and '-', at most
# 32 characters, not ending in '-'.
bad_name() { echo "the agent name is 1 to 32 of a-z, 0-9 and '-', starting with a letter, not ending with '-' (like toronto-wg)" >&2; exit 2; }
case $agent in [a-z]*) ;; *) bad_name ;; esac
case $agent in *[!a-z0-9-]* | *-) bad_name ;; esac
[ "${#agent}" -le 32 ] || bad_name

ssh "$@" "$host" "BF_PROTOCOL=$protocol BF_AGENT=$agent sh -s" <<'REMOTE'
set -eu
protocol=$BF_PROTOCOL
agent=$BF_AGENT
mark="# Made by deploy/node-add-protocol.sh (Barely-free, specs/dual-protocol.md)."

# Extra ports reach the same interface through a redirect on the public side only
# (specs/dual-protocol.md): DNS and time for WireGuard, IPsec's NAT port for AmneziaWG.
if [ "$protocol" = wireguard ]; then
  dev=wg0; tool=wg; quick=wg-quick; conf=/etc/wireguard/wg0.conf
  range=10.78.0.0/16; address=10.78.0.1/16; port=51820; extra_ports="53 123"
else
  dev=awg0; tool=awg; quick=awg-quick; conf=/etc/amnezia/amneziawg/awg0.conf
  range=10.77.0.0/16; address=10.77.0.1/16; port=443; extra_ports="4500"
fi
unit=bf-agent-$protocol.service
secret=/etc/barely-free/agent-$agent.secret
site=/etc/caddy/barely-free-agent-$agent.caddy
listen=127.0.0.1:9871

keep() { [ ! -e "$1" ] || [ -e "$1.before-dual" ] || cp -p "$1" "$1.before-dual"; }

# ---- the first agent must not already be this one ----
first=/etc/systemd/system/bf-agent.service
[ -f "$first" ] || { echo "$first is not there: install the first agent (deploy/deploy-agent.sh) first" >&2; exit 1; }
if grep -qx "Environment=BF_INTERFACE=$dev" "$first"; then
  echo "the first agent (bf-agent.service) already drives $dev: this server has $protocol already" >&2
  exit 1
fi
grep -q '^Environment=BF_LISTEN=127.0.0.1:9870$' "$first" \
  || { echo "the first agent does not listen on 127.0.0.1:9870 as expected: not touching anything" >&2; exit 1; }

# ---- the kernel module (AmneziaWG only) ----
if [ "$protocol" = amneziawg ]; then
  [ -d /sys/module/amneziawg ] || modprobe amneziawg 2>/dev/null || true
  if [ ! -d /sys/module/amneziawg ]; then
    # Amnezia's own package archive, pinned to its full signing key. The archive has only
    # Ubuntu series; the module is built here for this kernel (DKMS) and the tools are
    # plain programs, so the newest LTS series is used.
    key=75C9DD72C799870E310542E24166F2C257290828
    keyring=/etc/apt/keyrings/amnezia.gpg
    install -d -m 0755 /etc/apt/keyrings
    if [ ! -s "$keyring" ]; then
      home=$(mktemp -d)
      drop() { GNUPGHOME=$home gpgconf --kill all 2>/dev/null || true; rm -rf "$home"; }
      GNUPGHOME=$home gpg --batch --quiet --keyserver hkps://keyserver.ubuntu.com --recv-keys "$key"
      GNUPGHOME=$home gpg --batch --with-colons --fingerprint "$key" | grep -q "^fpr:::::::::$key:" \
        || { drop; echo "the key fetched is not Amnezia's ($key)" >&2; exit 1; }
      GNUPGHOME=$home gpg --batch --export "$key" > "$keyring"
      drop
    fi
    # Only Amnezia's own packages may come from that archive.
    install -d -m 0755 /etc/apt/preferences.d
    printf 'Package: *\nPin: origin ppa.launchpadcontent.net\nPin-Priority: 1\n\nPackage: amneziawg*\nPin: origin ppa.launchpadcontent.net\nPin-Priority: 500\n' \
      > /etc/apt/preferences.d/amnezia
    echo "deb [signed-by=$keyring] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu noble main" \
      > /etc/apt/sources.list.d/amnezia.list
    DEBIAN_FRONTEND=noninteractive apt-get update -q
    # linux-headers-amd64 follows every new kernel, so DKMS can rebuild the module after an
    # upgrade. A build that fails is undone, so no later apt run trips over it.
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -q "linux-headers-$(uname -r)" linux-headers-amd64 \
      amneziawg-dkms amneziawg-tools; then
      DEBIAN_FRONTEND=noninteractive apt-get purge -y -q amneziawg-dkms amneziawg-tools amneziawg 2>/dev/null || true
      rm -f /etc/apt/sources.list.d/amnezia.list /etc/apt/preferences.d/amnezia
      DEBIAN_FRONTEND=noninteractive apt-get update -q || true
      echo "installing AmneziaWG failed (the kernel module did not build?): undone, nothing else changed" >&2
      exit 1
    fi
    modprobe amneziawg
  fi
  # Without the kernel module awg-quick quietly falls back to a slower userspace program.
  [ -d /sys/module/amneziawg ] || { echo "the amneziawg kernel module is not loaded after installing: stopping" >&2; exit 1; }
fi

# ---- the interface ----
if [ -f "$conf" ] && grep -qxF "$mark" "$conf"; then
  echo "$dev: already set up by this script"
else
  # The range must be free on this server (on Dallas, wg0 holds 10.77 until
  # deploy/node-wireguard-range.sh moves it).
  if ip -4 -o addr show | grep -q " inet ${address%/*}/"; then
    echo "${address%/*} is already on an interface of this server; for AmneziaWG on Dallas run deploy/node-wireguard-range.sh first" >&2
    exit 1
  fi
  if [ -n "$(ss -Hlun "sport = :$port")" ]; then
    echo "something already listens on UDP $port (Caddy's HTTP/3? deploy/deploy-caddy.sh turns it off on 443)" >&2
    exit 1
  fi
  if systemctl is-active --quiet "$quick@$dev"; then
    echo "$dev is running with a setup this script did not make: not replacing it" >&2
    exit 1
  fi
  wan=$(ip -o route get 1.1.1.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p')
  [ -n "$wan" ] || { echo "cannot tell which interface reaches the internet" >&2; exit 1; }
  install -d -m 0700 "$(dirname "$conf")"
  umask 077
  private=$($tool genkey)
  {
    echo "$mark"
    echo "[Interface]"
    echo "Address = $address"
    echo "ListenPort = $port"
    echo "PrivateKey = $private"
    if [ "$protocol" = amneziawg ]; then
      # Must match AMNEZIA_PARAMS in crates/bf-control/src/app.rs and Toronto's awg0.
      printf 'Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 20\n'
      printf 'H1 = 1000000001\nH2 = 1000000002\nH3 = 1000000003\nH4 = 1000000004\n'
    fi
    echo "PostUp = sysctl -w net.ipv4.ip_forward=1"
    echo "PostUp = iptables -I FORWARD 1 -i %i -j ACCEPT"
    echo "PostUp = iptables -I FORWARD 1 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    echo "PostUp = iptables -I FORWARD 1 -i %i -o %i -j DROP"
    echo "PostUp = iptables -t nat -A POSTROUTING -s $range -o $wan -j MASQUERADE"
    echo "PostUp = iptables -t mangle -A FORWARD -o $wan -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
    for extra in $extra_ports; do
      echo "PostUp = iptables -t nat -A PREROUTING -i $wan -p udp --dport $extra -j REDIRECT --to-ports $port"
    done
    echo "PostDown = iptables -D FORWARD -i %i -j ACCEPT"
    echo "PostDown = iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    echo "PostDown = iptables -D FORWARD -i %i -o %i -j DROP"
    echo "PostDown = iptables -t nat -D POSTROUTING -s $range -o $wan -j MASQUERADE"
    echo "PostDown = iptables -t mangle -D FORWARD -o $wan -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
    for extra in $extra_ports; do
      echo "PostDown = iptables -t nat -D PREROUTING -i $wan -p udp --dport $extra -j REDIRECT --to-ports $port"
    done
  } > "$conf.new"
  chmod 0600 "$conf.new"
  umask 022
  # Checked before it is put in place; the tool reads the interface name from the file name.
  check=$(mktemp -d)
  cp "$conf.new" "$check/$dev.conf"
  if ! $quick strip "$check/$dev.conf" >/dev/null; then
    rm -rf "$check" "$conf.new"
    echo "the new $dev setup does not parse: nothing was changed" >&2
    exit 1
  fi
  rm -rf "$check"
  keep "$conf"
  mv "$conf.new" "$conf"
  echo "$dev: $address on UDP $port (also $extra_ports from outside)"
fi
# Every run: a first run that stopped here is finished by the next one.
ufw allow "$port/udp" >/dev/null
systemctl enable --now "$quick@$dev" >/dev/null
systemctl is-active --quiet "$quick@$dev" || { echo "$dev did not start: see journalctl -u $quick@$dev" >&2; exit 1; }

# ---- the second agent ----
install -d -m 0750 /etc/barely-free
if [ ! -s "$secret" ]; then
  (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$secret")
  echo "made $secret"
fi
chmod 600 "$secret"
if [ "$protocol" = wireguard ]; then from_dev=awg0; from_quick=awg-quick; from_tool=awg; else from_dev=wg0; from_quick=wg-quick; from_tool=wg; fi
sed \
  -e "s#^Description=.*#Description=Barely-free node agent ($protocol, $dev)#" \
  -e "s#$from_quick@$from_dev#$quick@$dev#g" \
  -e "s#^Environment=BF_LISTEN=127.0.0.1:9870\$#Environment=BF_LISTEN=$listen#" \
  -e "s#^Environment=BF_INTERFACE=$from_dev\$#Environment=BF_INTERFACE=$dev#" \
  -e "s#^Environment=BF_WG_BIN=/usr/bin/$from_tool\$#Environment=BF_WG_BIN=/usr/bin/$tool#" \
  -e "s#^Environment=BF_STATE_DIR=/var/lib/barely-free\$#Environment=BF_STATE_DIR=/var/lib/barely-free-$agent#" \
  -e "s#^StateDirectory=barely-free\$#StateDirectory=barely-free-$agent#" \
  -e "s#^LoadCredential=agent.secret:/etc/barely-free/agent.secret\$#LoadCredential=agent.secret:$secret#" \
  "$first" > "/etc/systemd/system/$unit.new"
for line in "Environment=BF_LISTEN=$listen" "Environment=BF_INTERFACE=$dev" "Environment=BF_WG_BIN=/usr/bin/$tool" \
  "Environment=BF_STATE_DIR=/var/lib/barely-free-$agent" "StateDirectory=barely-free-$agent" \
  "LoadCredential=agent.secret:$secret" "Wants=$quick@$dev.service"; do
  grep -qxF "$line" "/etc/systemd/system/$unit.new" || {
    rm -f "/etc/systemd/system/$unit.new"
    echo "the first agent's unit is not shaped as expected (no $line after the change): not installing $unit" >&2
    exit 1
  }
done
keep "/etc/systemd/system/$unit"
mv "/etc/systemd/system/$unit.new" "/etc/systemd/system/$unit"
systemctl daemon-reload
systemctl enable --now "$unit" >/dev/null
systemctl restart "$unit"

# ---- Caddy: the agent's own name on :8443 ----
caddyfile=/etc/caddy/Caddyfile
printf '%s\n%s.agent.internal:8443 {\n\ttls internal\n\theader -Server\n\treverse_proxy %s\n}\n' \
  "$mark" "$agent" "$listen" > "$site"
# This run's starting point, to go back to if Caddy refuses (the first run's copy stays too).
snapshot=$(mktemp)
cp -p "$caddyfile" "$snapshot"
if ! grep -qxF "import $site" "$caddyfile"; then
  keep "$caddyfile"
  printf '\n# The %s agent over HTTPS (deploy/node-add-protocol.sh)\nimport %s\n' "$protocol" "$site" >> "$caddyfile"
fi
if ! runuser -u caddy -- env HOME=/var/lib/caddy caddy validate --config "$caddyfile" --adapter caddyfile >/dev/null 2>&1; then
  cp -p "$snapshot" "$caddyfile"
  rm -f "$snapshot"
  echo "caddy rejects the new configuration: the Caddyfile is back as it was" >&2
  exit 1
fi
rm -f "$snapshot"
systemctl reload caddy

# ---- check ----
i=0
until BF_LISTEN=$listen BF_SECRET_FILE=$secret bf-agent probe >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -lt 10 ] || { echo "the $protocol agent does not answer on $listen" >&2; exit 1; }
  sleep 1
done
echo "$unit: $(systemctl is-active "$unit"), answering on $listen"
echo
echo "Now, on your Mac (the secret goes node -> VM through your own ssh; deploy/node-roots/$agent.pem"
echo "must be in the repo: the same Caddy CA as this server's first agent):"
echo "  deploy/deploy-web.sh root@web.example.ts.net"
echo "  deploy/set-node-secret.sh $agent \"<this server's ssh args>\" \"root@web.example.ts.net\" $secret"
echo "and on the VM:"
echo "  bf-control node add $agent <this server's ip>:8443 <Title> <Place> --protocol $protocol"
echo "  bf-control node check $agent"
REMOTE

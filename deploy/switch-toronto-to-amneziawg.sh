#!/bin/sh
# Stage Toronto's switch to the AmneziaWG kernel module on Debian's 6.12.116 kernel.
# Keeps the existing 10.77.0.0/16 peer pool and bf-agent reconciliation. Does not reboot;
# reboot only after the module build, staged service and boot entry have been checked.
# Run: deploy/switch-toronto-to-amneziawg.sh root@192.0.2.176 -i ~/.ssh/your_key
set -eu

host=${1:?usage: deploy/switch-toronto-to-amneziawg.sh <user@host> [ssh options...]}
shift

ssh "$@" "$host" 'sh -s' <<'REMOTE'
set -eu

kernel=6.12.116+deb13-amd64
module=/lib/modules/$kernel/updates/dkms/amneziawg.ko.xz
[ -s "$module" ] || { echo "AmneziaWG is not built for $kernel" >&2; exit 1; }
dkms status amneziawg | grep -F "$kernel" | grep -F installed >/dev/null || {
  echo "DKMS does not report an installed AmneziaWG module for $kernel" >&2; exit 1;
}
command -v /usr/bin/awg >/dev/null || { echo "AmneziaWG tools are missing" >&2; exit 1; }
systemctl is-active --quiet wg-quick@wg0 || { echo "wg0 is not active; refusing to stage the switch" >&2; exit 1; }
[ ! -e /etc/amnezia/amneziawg/awg0.conf ] || { echo "awg0 config already exists; refusing to overwrite it" >&2; exit 1; }

backup=/root/bf-before-amnezia-$(date +%Y%m%d%H%M%S)
mkdir -m 0700 "$backup"
cp -a /etc/wireguard/wg0.conf "$backup/wg0.conf"
cp -a /etc/systemd/system/bf-agent.service "$backup/bf-agent.service"
cp -a /etc/systemd/system/awg-quick@.service "$backup/awg-quick@.service" 2>/dev/null || true
echo "$backup" > /root/bf-amnezia-backup-path

install -d -m 0700 /etc/amnezia/amneziawg
umask 077
server_private=$(/usr/bin/awg genkey)
wan=$(ip -o route get 1.1.1.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p')
[ -n "$wan" ] || { echo "cannot determine internet interface" >&2; exit 1; }

cat > /etc/amnezia/amneziawg/awg0.conf <<EOF_CONFIG
[Interface]
Address = 10.77.0.1/16
ListenPort = 443
PrivateKey = $server_private
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 20
H1 = 1000000001
H2 = 1000000002
H3 = 1000000003
H4 = 1000000004
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -I FORWARD 1 -i %i -j ACCEPT
PostUp = iptables -I FORWARD 1 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -I FORWARD 1 -i %i -o %i -j DROP
PostUp = iptables -t nat -A POSTROUTING -s 10.77.0.0/16 -o $wan -j MASQUERADE
PostUp = iptables -t mangle -A FORWARD -o $wan -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -D FORWARD -i %i -o %i -j DROP
PostDown = iptables -t nat -D POSTROUTING -s 10.77.0.0/16 -o $wan -j MASQUERADE
PostDown = iptables -t mangle -D FORWARD -o $wan -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
EOF_CONFIG
chmod 0600 /etc/amnezia/amneziawg/awg0.conf

# Replace the failed userspace override with Amnezia's kernel-interface service.
cp /lib/systemd/system/awg-quick@.service /etc/systemd/system/awg-quick@.service
sed \
  -e 's/wg-quick@wg0/awg-quick@awg0/g' \
  -e 's/Environment=BF_INTERFACE=wg0/Environment=BF_INTERFACE=awg0/' \
  -e 's#Environment=BF_WG_BIN=/usr/bin/wg#Environment=BF_WG_BIN=/usr/bin/awg#' \
  /etc/systemd/system/bf-agent.service > /etc/systemd/system/bf-agent.service.new
mv /etc/systemd/system/bf-agent.service.new /etc/systemd/system/bf-agent.service
ufw allow 443/udp
systemctl daemon-reload
/usr/bin/awg-quick strip awg0 >/dev/null
systemd-analyze verify /etc/systemd/system/awg-quick@.service /etc/systemd/system/bf-agent.service
systemctl disable wg-quick@wg0 >/dev/null
systemctl enable awg-quick@awg0 >/dev/null
update-grub >/dev/null

printf 'Staged backups: %s\n' "$backup"
echo "Kernel module: $(dkms status amneziawg | grep -F "$kernel")"
echo "Next kernel: $(readlink -f /vmlinuz)"
echo "Current WireGuard remains up until reboot. AmneziaWG will start on UDP 443 after reboot."
REMOTE

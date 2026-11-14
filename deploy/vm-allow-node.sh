#!/bin/sh
# Lets the web VM's firewall pass the control program's calls to one node's agent.
#
# The VM's /etc/nftables.conf rejects all outbound traffic except ssh to a set of old VPN
# fleet addresses (`happ_fleet`), a deliberate guard so no VPN traffic runs on that machine.
# Dallas (198.51.100.185) is in that set, so the poller's HTTPS calls to its agent on port 8443
# are refused with a TCP reset before they leave the VM. This adds ONE accept rule, for that
# one address and that one port, ahead of the reject: nothing else changes.
#
# Run it yourself (it changes the VM's firewall):
#   deploy/vm-allow-node.sh <node ip> root@<vm ip> -o Port=<ssh port>
#   deploy/vm-allow-node.sh 198.51.100.185 root@web.example.ts.net
#
# It keeps a copy of the file as /etc/nftables.conf.before-agent-port, checks the new file
# with `nft -c`, applies the rule to the running firewall, and is safe to run again.
set -eu

ip=${1:?usage: deploy/vm-allow-node.sh <node ip> <user@vm> [ssh options...]}
host=${2:?usage: deploy/vm-allow-node.sh <node ip> <user@vm> [ssh options...]}
shift 2

case $ip in
  *[!0-9.]* | '' | *..* | .* | *.) echo "the node address must be an IPv4 address like 198.51.100.185" >&2; exit 2 ;;
esac
[ "$(printf '%s' "$ip" | tr -cd . | wc -c | tr -d ' ')" = 3 ] || { echo "the node address must be an IPv4 address like 198.51.100.185" >&2; exit 2; }

ssh "$@" "$host" "NODE_IP=$ip sh -s" <<'REMOTE'
set -eu
conf=/etc/nftables.conf
rule="ip daddr $NODE_IP tcp dport 8443 accept"
[ -f "$conf" ] || { echo "$conf is not there" >&2; exit 1; }
grep -q 'ip daddr @happ_fleet tcp dport != 22 reject with tcp reset' "$conf" \
  || { echo "the reject rule this script goes in front of is not in $conf; nothing was changed" >&2; exit 1; }

# The file, so a reboot keeps it.
if ! grep -q "^[[:space:]]*$rule\$" "$conf"; then
  cp -n "$conf" "$conf.before-agent-port"
  awk -v rule="$rule" '
    !done && /ip daddr @happ_fleet tcp dport != 22 reject with tcp reset/ { print "\t\t" rule; done = 1 }
    { print }
  ' "$conf" > "$conf.new"
  nft -c -f "$conf.new" || { rm -f "$conf.new"; echo "the new file does not check out; nothing was changed" >&2; exit 1; }
  cat "$conf.new" > "$conf"
  rm -f "$conf.new"
fi

# The running firewall, ahead of the rejects.
nft list chain inet filter output | grep -q "$rule" || nft insert rule inet filter output $rule

echo "output chain now:"
nft list chain inet filter output
if (timeout 6 bash -c "echo > /dev/tcp/$NODE_IP/8443") 2>/dev/null; then
  echo "$NODE_IP:8443 is reachable from here"
else
  echo "$NODE_IP:8443 is still not reachable from here" >&2
fi
REMOTE

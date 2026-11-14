#!/bin/bash
# Teaches the website every SSH login of the last 90 days on all three servers, so the login
# alerts (specs/login-alerts.md) start quiet: those (key, network) pairs never cause an email.
# Run it from the Mac once, right after the first deploy-web.sh that has the login alerts:
#
#   deploy/seed-known-logins.sh
#
# Each server's journal goes straight into `bf-control logins learn` on the VM (run as the
# website's user, which owns the file) through this Mac's memory only: nothing is written
# here, and only `Accepted` lines leave a server. The website restarts at the end so it
# reads the new pairs. Safe to run again: learning only adds.
#
# Settings, with this project's servers as defaults (their Tailscale names: since
# 2026-11-12 the servers take SSH only over Tailscale, decision 024):
#   BF_VM=root@web.example.ts.net   BF_VM_PORT=22
#   BF_NODES="root@dallas.example.ts.net root@toronto.example.ts.net"   BF_NODE_KEY=~/.ssh/your_key
#   BF_SEED_DAYS=90
set -euo pipefail

vm=${BF_VM:-root@web.example.ts.net}
vm_port=${BF_VM_PORT:-22}
nodes=${BF_NODES:-root@dallas.example.ts.net root@toronto.example.ts.net}
node_key=${BF_NODE_KEY:-$HOME/.ssh/your_key}
days=${BF_SEED_DAYS:-90}
case $days in
  '' | *[!0-9]*)
    echo "BF_SEED_DAYS must be a whole number of days" >&2
    exit 2
    ;;
esac

# Run by root's shell on each server; pipefail so a journal that cannot be read fails.
journal="set -o pipefail; journalctl -u ssh -o short-unix --no-pager --quiet --since=-${days}d | awk '/: Accepted (publickey|password) for /'"
learn='runuser -u barely-free -- /usr/local/bin/bf-control logins learn && systemctl try-restart bf-control.service'

{
  echo "reading the VM's logins" >&2
  ssh -o Port="$vm_port" "$vm" "$journal"
  for node in $nodes; do
    echo "reading $node's logins" >&2
    ssh -i "$node_key" -o IdentitiesOnly=yes "$node" "$journal"
  done
} | ssh -o Port="$vm_port" "$vm" "$learn"

#!/bin/bash
# Gives the web VM a copy of one node's signing secret. Run it yourself: the secret goes
# from the node to the VM through your own ssh, one command piped into the other. It is
# never put in a variable, on a command line, on screen, in a file on this Mac or in the
# shell history. Claude does not handle secrets.
#
#   deploy/set-node-secret.sh <name> "<ssh arguments for the node>" "<ssh arguments for the VM>" [secret file]
#
#   deploy/set-node-secret.sh toronto \
#     "root@toronto.example.ts.net -i ~/.ssh/your_key -o IdentitiesOnly=yes" \
#     "root@<vm ip> -o Port=<ssh port>"
#
# <name> is the name the node is registered under (bf-control node add <name> ...). The
# secret is read from /etc/barely-free/agent.secret on the node, or, for a server's second
# agent (deploy/node-add-protocol.sh), from the file given, which must be
# /etc/barely-free/agent-<agent name>.secret (without it, the script refuses a name that has
# such a file on the server, so the first agent's secret never lands under a second agent's
# name). It is installed as
# /etc/barely-free/nodes/<name>.secret on the VM: owned by the website user, mode 0400.
# Nothing is installed unless what arrives is one line of hex, an even number of at least 64
# characters (at most 1 KiB is read).
#
# It then prints the first 8 characters of the file's SHA-256 as worked out at each end, so
# you can see the two copies are the same without either secret being shown. Run
# deploy/deploy-web.sh first: it makes the website user and the folder, and installs the
# node's root certificate (deploy/node-roots/<name>.pem).
set -euo pipefail

usage='usage: deploy/set-node-secret.sh <name> "<ssh arguments for the node>" "<ssh arguments for the VM>" [secret file]'
name=${1:?$usage}
node_args=${2:?$usage}
vm_args=${3:?$usage}
file=${4:-/etc/barely-free/agent.secret}
[ $# -le 4 ] || { echo "$usage" >&2; exit 2; }
if ! [[ $file =~ ^/etc/barely-free/agent(-[a-z]([a-z0-9-]{0,30}[a-z0-9])?)?\.secret$ ]]; then
  echo "the secret file is /etc/barely-free/agent.secret or /etc/barely-free/agent-<agent name>.secret" >&2
  exit 2
fi

if ! [[ $name =~ ^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$ ]]; then
  echo "the name is 1 to 32 characters of a-z, 0-9 and -, starting with a letter and not ending with -" >&2
  exit 2
fi
read -r -a node <<< "$node_args"
read -r -a vm <<< "$vm_args"
[ "${#node[@]}" -ge 1 ] && [ "${#vm[@]}" -ge 1 ] || { echo "$usage" >&2; exit 2; }

# Without the fourth argument the first agent's secret is read. If this name has a secret
# file of its own on the server, it is a second agent, and that would install the wrong
# secret under its name: stop before anything is read. ($name is checked above.)
if [ $# -lt 4 ]; then
  own=/etc/barely-free/agent-$name.secret
  status=0
  ssh "${node[@]}" "test -e $own" || status=$?
  case $status in
    0) echo "the server has $own, so $name is a second agent: give that file as the fourth argument" >&2
       exit 2 ;;
    1) ;;
    *) echo "could not ask the node whether $own exists (ssh exit $status); nothing was done" >&2
       exit 1 ;;
  esac
fi

read -r -d '' remote <<'REMOTE' || true
set -eu
umask 077
dir=/etc/barely-free/nodes
getent passwd barely-free >/dev/null || { echo "there is no barely-free user on this machine; run deploy/deploy-web.sh first" >&2; exit 1; }
install -d -o root -g barely-free -m 0750 /etc/barely-free "$dir"
tmp=$(mktemp "$dir/.incoming.XXXXXX")
trap 'rm -f "$tmp"' EXIT
head -c 1024 > "$tmp"
if [ "$(grep -c '' "$tmp")" != 1 ] || ! sed 's/[[:space:]]*$//;s/^[[:space:]]*//' "$tmp" | grep -Eq '^([0-9a-fA-F]{2}){32,}$'; then
  echo "what arrived is not a hex secret of at least 64 characters; nothing was installed" >&2
  exit 1
fi
chown barely-free:barely-free "$tmp"
chmod 0400 "$tmp"
mv "$tmp" "$dir/NODE_NAME.secret"
trap - EXIT
REMOTE
remote=${remote//NODE_NAME/$name}

# $file is checked above: one of the agents' secret files, nothing else.
ssh "${node[@]}" "cat $file" | ssh "${vm[@]}" "$remote"

on_node=$(ssh "${node[@]}" "sha256sum $file" | cut -c1-8)
on_vm=$(ssh "${vm[@]}" "sha256sum /etc/barely-free/nodes/$name.secret" | cut -c1-8)
echo "node $name: first 8 characters of the secret's SHA-256: on the node $on_node, on the VM $on_vm"
if [ -n "$on_node" ] && [ "$on_node" = "$on_vm" ]; then
  echo "they match; /etc/barely-free/nodes/$name.secret is in place"
else
  echo "THEY DO NOT MATCH: do not use this copy" >&2
  exit 1
fi

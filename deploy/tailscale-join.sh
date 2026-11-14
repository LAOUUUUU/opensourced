#!/bin/bash
# Puts one server on the admin's tailnet, so SSH can later be reached only through Tailscale
# (research/tailscale-ssh/RESEARCH.md, decision 024). Run it yourself: it asks for the auth
# key with a hidden prompt, so the key never appears on screen, in the shell history, in a
# command line on either machine, or in a file on this Mac. Claude does not type secrets.
#
#   deploy/tailscale-join.sh <name> <user@host> [ssh options...]
#   deploy/tailscale-join.sh dallas root@198.51.100.185 -i ~/.ssh/your_key -o IdentitiesOnly=yes
#   deploy/tailscale-join.sh web root@203.0.113.50 -o Port=2222
#
# Make the key first in Tailscale's admin console: one-off (not reusable), pre-tagged
# (tag:node for Dallas and Toronto, tag:web for the VM), one per server. The tag comes from
# the key, so nothing here names it.
#
# On the server (Debian 13 "trixie" only), in one SSH connection:
#   - Tailscale is installed if it is not there, from Tailscale's stable apt repository,
#     signed by the key in deploy/tailscale-archive-keyring.gpg (checked into this repo,
#     2026-11-12: fingerprint 2596 A99E AAB3 3821 893C 0A79 458C A832 957F 5868);
#   - the auth key is kept in a file in /run that only root can read, for
#     `tailscale up --auth-key=file:<it>`, and removed when the script ends, whatever happens;
#   - it joins as <name>, with Tailscale SSH off (normal OpenSSH stays the way in, keys still
#     required) and the server's own DNS left alone (--accept-dns=false).
# Nothing is closed: public SSH stays open until SSH over Tailscale has been tested.
set -euo pipefail

usage="usage: deploy/tailscale-join.sh <name> <user@host> [ssh options...]   (name: dallas, toronto, web)"
name=${1:-}
host=${2:-}
case $name in
  '' | -* | *[!a-z0-9-]*)
    echo "$usage" >&2
    exit 2
    ;;
esac
if [ "${#name}" -gt 63 ] || [ -z "$host" ]; then
  echo "$usage" >&2
  exit 2
fi
shift 2

root=$(cd "$(dirname "$0")/.." && pwd)
keyring="$root/deploy/tailscale-archive-keyring.gpg"
[ -s "$keyring" ] || {
  echo "missing $keyring" >&2
  exit 1
}

key=""
read -rsp "Tailscale auth key for $name (one-off, tagged): " key || true
echo >&2
case $key in
  tskey-auth-*) ;;
  *)
    unset key
    echo "that is not a Tailscale auth key (an auth key starts with tskey-auth-)" >&2
    exit 1
    ;;
esac
case ${key#tskey-auth-} in
  '' | *[!A-Za-z0-9-]*)
    unset key
    echo "that key has characters a Tailscale auth key never has" >&2
    exit 1
    ;;
esac

# The server's login shell reads the key (the first line) into a private file, then runs
# the rest of what arrives as the script, with that file and the name as its arguments.
bootstrap="umask 077 && f=\$(mktemp /run/bf-tailscale-key.XXXXXX) && IFS= read -r k && printf '%s\\n' \"\$k\" > \"\$f\" && unset k && exec sh -s \"\$f\" $name"

# The bootstrap is built here on purpose; only the name goes into it, checked above.
# shellcheck disable=SC2029
{
  printf '%s\n' "$key"
  printf 'keyring=%s\n' "$(base64 <"$keyring" | tr -d '\n')"
  cat <<'REMOTE'
set -eu
key_file=$1
name=$2
trap 'rm -f "$key_file"' EXIT
if ! command -v tailscale >/dev/null 2>&1; then
  . /etc/os-release
  if [ "${VERSION_CODENAME:-}" != trixie ]; then
    echo "this server runs ${PRETTY_NAME:-an unknown system}; only Debian 13 (trixie) is set up here" >&2
    exit 1
  fi
  install -d -m 0755 /usr/share/keyrings
  printf '%s' "$keyring" | base64 -d >/usr/share/keyrings/tailscale-archive-keyring.gpg.new
  chmod 0644 /usr/share/keyrings/tailscale-archive-keyring.gpg.new
  mv -f /usr/share/keyrings/tailscale-archive-keyring.gpg.new /usr/share/keyrings/tailscale-archive-keyring.gpg
  printf 'deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/debian trixie main\n' >/etc/apt/sources.list.d/tailscale.list
  chmod 0644 /etc/apt/sources.list.d/tailscale.list
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y tailscale
fi
systemctl enable --now tailscaled
tailscale up --auth-key="file:$key_file" --hostname="$name" --accept-dns=false
echo "$name joined the tailnet: $(tailscale ip -4)"
REMOTE
} | ssh "$@" "$host" "$bootstrap"
unset key

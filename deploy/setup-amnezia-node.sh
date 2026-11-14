#!/bin/sh
# Set up a dedicated AmneziaWG trial node on a clean Ubuntu/Debian x86-64 host.
# Does not touch the existing WireGuard nodes. Run against a new host you control:
#   deploy/setup-amnezia-node.sh root@<new-node-ip> -i ~/.ssh/<key> -o IdentitiesOnly=yes
# The AmneziaWG packages come from the official Amnezia repository. Review the host's
# distro and firewall first; this installs a kernel module and opens UDP 443.
set -eu

host=${1:?usage: deploy/setup-amnezia-node.sh <user@host> [ssh options...]}
shift

ssh "$@" "$host" 'sh -s' <<'REMOTE'
set -eu

[ "$(uname -m)" = x86_64 ] || { echo "trial setup supports x86_64 only" >&2; exit 1; }
[ -r /etc/os-release ] || { echo "cannot identify Linux distribution" >&2; exit 1; }
. /etc/os-release
case "${ID:-}" in ubuntu|debian) ;; *) echo "trial setup supports Ubuntu or Debian" >&2; exit 1;; esac

if command -v awg >/dev/null 2>&1 || [ -e /etc/amnezia/amneziawg ]; then
  echo "AmneziaWG appears already installed; refusing to overwrite it" >&2
  exit 1
fi
if [ -e /etc/wireguard/wg0.conf ]; then
  echo "this host already has wg0; use a clean trial host to avoid disrupting VPN service" >&2
  exit 1
fi

if [ "$ID" = ubuntu ]; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common python3-launchpadlib gnupg2 "linux-headers-$(uname -r)"
  add-apt-repository -y ppa:amnezia/ppa
else
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common python3-launchpadlib gnupg2 "linux-headers-$(uname -r)"
  apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828
  printf '%s\n' 'deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main' 'deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main' >> /etc/apt/sources.list.d/amneziawg.list
  apt-get update
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y amneziawg
modprobe amneziawg
awg --version
echo "AmneziaWG installed. Server setup remains a separate, reviewed step; UDP 443 must be allowed by the provider firewall."
REMOTE

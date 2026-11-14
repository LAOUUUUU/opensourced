#!/bin/bash
# Puts the Resend API key on the web VM. Run it yourself: it asks for the key with a
# hidden prompt, so the key never appears on screen, in the shell history, or in a file on
# this Mac. Claude does not type secrets.
#
#   deploy/set-resend-key.sh root@<vm ip> -o Port=<ssh port>
#
# The key is written to /etc/barely-free/resend.key on the VM (mode 0600, owned by the
# dedicated website user when it exists). Make the
# key in Resend with "sending access" and limit it to the one sending domain, so a leak
# can only send mail from that domain and nothing else.
set -euo pipefail

host=${1:?usage: deploy/set-resend-key.sh <user@host> [ssh options...]}
shift

read -rsp 'Resend API key (sending access, one domain): ' key
echo
[ -n "$key" ] || { echo "no key given" >&2; exit 1; }

printf '%s\n' "$key" | ssh "$@" "$host" \
  'install -d -m 0750 /etc/barely-free && umask 077 && cat > /etc/barely-free/resend.key.new && mv /etc/barely-free/resend.key.new /etc/barely-free/resend.key && chmod 600 /etc/barely-free/resend.key && if getent passwd barely-free >/dev/null 2>&1; then chown barely-free:barely-free /etc/barely-free/resend.key && chgrp barely-free /etc/barely-free; fi && echo "stored /etc/barely-free/resend.key ($(wc -c < /etc/barely-free/resend.key) bytes, mode 600)"'
unset key

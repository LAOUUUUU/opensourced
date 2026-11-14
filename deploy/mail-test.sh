#!/bin/bash
# Sends one real sign-in email through Resend, so you can see it in an inbox. Run it
# yourself, on this Mac: it asks for the Resend key with a hidden prompt, so the key never
# appears on screen, in the shell history, on a command line, or in a file that stays
# behind. Claude does not type, store or use keys.
#
#   deploy/mail-test.sh you@example.com
#
# The key goes into a temporary file that only you can read, `bf-control mail-test` reads
# it from there, and the file is deleted when the script ends, even if it fails or you
# press Ctrl-C. Nothing is installed on the server and nothing is kept.
#
# Use a Resend key with "sending access" limited to the sending domain
# (barely-free.com), and delete or rotate it when you are done.
#
# BF_BIN names another bf-control to run (the tests use it); without it the script builds
# and runs target/debug/bf-control.
set -euo pipefail

to=${1:?usage: deploy/mail-test.sh <your email address>}

root=$(cd "$(dirname "$0")/.." && pwd)
bin=${BF_BIN:-}
if [ -z "$bin" ]; then
  (cd "$root" && cargo build --quiet -p bf-control)
  bin=$root/target/debug/bf-control
fi

umask 077
keyfile=$(mktemp "${TMPDIR:-/tmp}/bf-resend-key.XXXXXX")
cleanup() { rm -f "$keyfile"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

read -rsp 'Resend API key (it is not shown): ' key
echo
[ -n "$key" ] || { echo "no key given" >&2; exit 1; }
printf '%s\n' "$key" > "$keyfile"
unset key

BC_RESEND_KEY_FILE=$keyfile "$bin" mail-test "$to"

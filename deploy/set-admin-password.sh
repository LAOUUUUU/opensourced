#!/bin/bash
# Sets the admin password of one account on the web VM. Run it yourself: it asks for the
# password twice with a hidden prompt, so the password never appears on screen, in the shell
# history, in a process list, or in a file on this Mac. Claude does not type secrets.
#
#   deploy/set-admin-password.sh <account-id> root@<vm ip> -o Port=<ssh port>
#
# The account must be an admin already. On the VM, once:
#   runuser -u barely-free -- /usr/local/bin/bf-control admin grant <account-id>
#
# The password goes over ssh on standard input, straight into
#   bf-control admin set-password <account-id>
# which keeps only an Argon2id hash of it. It needs at least 12 characters. Run the script
# again to change the password; that also clears a lock from too many wrong tries.
set -euo pipefail

usage="usage: deploy/set-admin-password.sh <account-id> <user@host> [ssh options...]"
account=${1:?$usage}
host=${2:?$usage}
shift 2

# The id becomes part of the command that runs on the VM, so only a plain number gets there.
case "$account" in
  '' | *[!0-9]*) echo "$usage" >&2; echo "the account id is a number" >&2; exit 2 ;;
esac
[ "${#account}" -le 18 ] || { echo "$usage" >&2; echo "that account id is too long" >&2; exit 2; }

# IFS= and -r keep the password exactly as typed: spaces at its ends, backslashes and all.
IFS= read -rsp 'Admin password (12 or more characters): ' password || true
echo >&2
IFS= read -rsp 'Again: ' again || true
echo >&2
[ -n "$password" ] || { echo "no password given; nothing was changed" >&2; exit 1; }
[ "$password" = "$again" ] || { echo "the two entries do not match; nothing was changed" >&2; exit 1; }

# The id is put into the remote command here on purpose; it is only digits (checked above).
# shellcheck disable=SC2029
# -T after the person's own options: a remote terminal would echo the password back.
if printf '%s\n' "$password" | ssh "$@" -T "$host" \
  "runuser -u barely-free -- /usr/local/bin/bf-control admin set-password $account"; then
  unset password again
else
  unset password again
  echo "the admin password was not set (the reason, if the program gave one, is above)" >&2
  exit 1
fi

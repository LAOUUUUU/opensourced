#!/bin/bash
# Barely-free: this server's recent SSH logins, for the "new login" email.
# Spec: specs/login-alerts.md, decision 023.
#
# Runs on all three servers, as root, once a minute (bf-logins.timer). The readers cannot
# read the journal or /root/.ssh: the website is the barely-free user, and the agents are
# dynamic users with no home. So this writes two files into /var/lib/barely-free-logins,
# which only the group bf-logins may read:
#   logins      the `Accepted` lines of the last 15 minutes (journalctl -o short-unix);
#   login-keys  `ssh-keygen -lf` of root's and each home's authorized_keys, which name
#               the keys.
# Both are replaced whole, so a reader never sees half a file. Failed and invalid logins are
# never copied. If the journal cannot be read the old files stay: they go stale, and the
# readers log that once. The unit makes the folder (root, group bf-logins, 0750) and gives
# the files the group. Installed as /usr/local/lib/barely-free/bf-logins.sh by
# deploy/deploy-web.sh (the VM) and deploy/deploy-agent.sh (the VPN servers).
set -euo pipefail
umask 027
export LC_ALL=C

dir=${BF_LOGINS_DIR:-/var/lib/barely-free-logins}
key_files=${BF_KEY_FILES:-/root/.ssh/authorized_keys /home/*/.ssh/authorized_keys}

since=$(($(date +%s) - 900))
logins=$(mktemp "$dir/.logins.XXXXXX")
keys=$(mktemp "$dir/.login-keys.XXXXXX")
trap 'rm -f "$logins" "$keys"' EXIT

journalctl -u ssh -o short-unix --no-pager --quiet --since="@$since" |
  awk '/: Accepted (publickey|password) for /' >"$logins"
# The list is split, and its globs expanded, on purpose.
# shellcheck disable=SC2086
for file in $key_files; do
  [ -f "$file" ] || continue
  ssh-keygen -lf "$file" >>"$keys" 2>/dev/null || true
done

# mktemp makes them 0600; the group reads them.
chmod 0640 "$logins" "$keys"
# The keys first, so fresh logins never meet older names.
mv -f "$keys" "$dir/login-keys"
mv -f "$logins" "$dir/logins"

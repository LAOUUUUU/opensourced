#!/bin/bash
# Barely-free: the web VM's nightly backup. Spec: specs/backup.md.
#
# Installed as /usr/local/lib/barely-free/bf-backup.sh and run by bf-backup.service (as the
# barely-free user, started by bf-backup.timer). Each night it:
#   1. copies the database with `bf-control backup` (one consistent snapshot, nothing deleted
#      left in it, the live database opened read-only);
#   2. packs that copy, the fingerprint key and a manifest of SHA-256 sums into a tar;
#   3. encrypts the tar with age to the public key(s) in the recipients file, so this VM can
#      lock a backup but never open one: the secret half is Lao's alone;
#   4. sends the encrypted file to every target over SSH, where a key that can only add a
#      new file receives it (deploy/bf-backup-receive), and the node keeps the newest 30.
# The plain copies exist only in a private folder under BACKUP_WORK (the service's runtime
# folder in /run, a tmpfs), removed on exit, whether it worked, failed or was stopped.
# One server failing does not stop the others. The outcome goes to BACKUP_STATUS, which
# the admin panel shows. No secret is ever on a command line.
#
# Exit 0 when every target took the file, 1 otherwise.
set -euo pipefail
umask 077
export LC_ALL=C

db=${BC_DB:-/var/lib/barely-free/control.db}
key=${BC_KEY_FILE:-/etc/barely-free/control.key}
recipients=${BACKUP_RECIPIENTS:-/etc/barely-free/backup.recipients}
targets_file=${BACKUP_TARGETS:-/etc/barely-free/backup-targets}
ssh_dir=${BACKUP_SSH_DIR:-/etc/barely-free/backup-ssh}
status=${BACKUP_STATUS:-/var/lib/barely-free/backup-status}
work=${BACKUP_WORK:-${RUNTIME_DIRECTORY:-}}
bf_control=${BF_CONTROL:-/usr/local/bin/bf-control}
export BC_DB=$db

file=""
sent=""
failed=""
error=""
run=""

write_status() {
  local tmp
  tmp=$(mktemp "$(dirname "$status")/.backup-status.XXXXXX") || return 1
  {
    echo "finished=$(date +%s)"
    echo "file=$file"
    echo "sent=${sent# }"
    echo "failed=${failed# }"
    echo "error=$(printf '%s' "$error" | tr '\n\r' '  ' | cut -c1-500)"
  } > "$tmp"
  mv -f -- "$tmp" "$status"
}

finish() {
  local code=$?
  trap - EXIT INT TERM
  if [ -n "$run" ]; then
    rm -rf -- "$run"
  fi
  if [ "$code" -ne 0 ] && [ -z "$error" ]; then
    error="the backup stopped unexpectedly (exit $code)"
  fi
  write_status || echo "bf-backup: could not write $status" >&2
  if [ -n "$error" ]; then
    echo "bf-backup: $error" >&2
  fi
  exit "$code"
}
trap finish EXIT
trap 'error="the backup was stopped"; exit 1' INT TERM

fail() {
  error=$*
  exit 1
}

# Only adds to the group/other "writable" check what the platform's `find` can test.
writable_by_others() {
  [ -n "$(find "$1" -prune \( -perm -0020 -o -perm -0002 \) -print)" ]
}

# --- check the settings before touching anything ---
[ -f "$recipients" ] || fail "there is no recipients file at $recipients"
writable_by_others "$recipients" && fail "the recipients file $recipients can be changed by others"
count=0
while IFS= read -r line || [ -n "$line" ]; do
  case $line in
    '' | '#'*) ;;
    age1*) count=$((count + 1)) ;;
    *) fail "the recipients file $recipients has a line that is not an age public key (age1...)" ;;
  esac
done < "$recipients"
[ "$count" -gt 0 ] || fail "the recipients file $recipients has no age public key"

[ -f "$targets_file" ] || fail "there is no targets file at $targets_file"
targets=()
while IFS= read -r line || [ -n "$line" ]; do
  case $line in
    '' | '#'*) continue ;;
  esac
  if [[ $line =~ ^bf-backup@[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    targets+=("$line")
  else
    fail "the targets file $targets_file has a line that is not bf-backup@<IPv4 address>"
  fi
done < "$targets_file"
[ "${#targets[@]}" -gt 0 ] || fail "the targets file $targets_file names no server"

[ -n "$work" ] && [ -d "$work" ] || fail "there is no work folder (BACKUP_WORK or RUNTIME_DIRECTORY)"

# --- copy, pack, encrypt ---
run=$(mktemp -d "$work/run.XXXXXX")
stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="control-$stamp.tar.age"

copy_said=$("$bf_control" backup "$run/control.db" 2>&1) || fail "$copy_said"
cp -- "$key" "$run/control.key" || fail "cannot read the key file $key"
{
  echo "made=$stamp"
  for f in control.db control.key; do
    echo "sha256 $(sha256sum "$run/$f" | cut -d' ' -f1) $f"
  done
} > "$run/manifest"
tar -C "$run" -cf - manifest control.db control.key \
  | age -R "$recipients" -o "$run/$name" 2> "$run/age.err" \
  || fail "the encryption failed: $(head -c 300 "$run/age.err")"
rm -f -- "$run/manifest" "$run/control.db" "$run/control.key"
file=$name
bytes=$(wc -c < "$run/$name" | tr -d ' ')

# --- send it to every server ---
last=""
for target in "${targets[@]}"; do
  ip=${target#bf-backup@}
  if ssh -F /dev/null \
      -i "$ssh_dir/id_ed25519" -o IdentitiesOnly=yes \
      -o UserKnownHostsFile="$ssh_dir/known_hosts" -o StrictHostKeyChecking=yes \
      -o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
      "$target" "put $name" < "$run/$name" > /dev/null 2> "$run/ssh.err"; then
    sent="$sent $ip"
  else
    failed="$failed $ip"
    last="$ip: $(head -c 300 "$run/ssh.err")"
  fi
done

if [ -n "$failed" ]; then
  fail "could not send $name to${failed} (${last})"
fi
echo "bf-backup: sent $name ($bytes bytes) to${sent}"

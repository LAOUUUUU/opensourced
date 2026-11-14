#!/bin/bash
# Sets up the web VM's nightly backup. Spec: specs/backup.md. Run it yourself, in three
# steps (the middle one is deploy/node-backup-receiver.sh, once per node):
#
#   1. deploy/setup-backup.sh root@<vm ip> <your age public key, age1...> -o Port=2222
#      Installs age (apt), /usr/local/lib/barely-free/bf-backup.sh, bf-backup.service and
#      bf-backup.timer (not started yet); makes the VM's backup SSH key as the barely-free
#      user in /etc/barely-free/backup-ssh (0700, made on the VM, so no private key
#      travels); writes /etc/barely-free/backup.recipients with your public key. The VM's
#      public backup key is saved to target/backup/vm-backup-key.pub on this Mac.
#   2. deploy/node-backup-receiver.sh root@<node ip> target/backup/vm-backup-key.pub ...
#      for each node; that also fills target/backup/known_hosts.
#   3. deploy/setup-backup.sh root@<vm ip> --finish target/backup/known_hosts -o Port=2222
#      Installs those host keys and the targets (bf-backup@<each node>), runs one backup
#      at once and prints its status, then starts the nightly timer. Exits 1 if that first
#      backup failed (the timer is started anyway, so the next night tries again).
#
# Your age secret key never comes near this script, the VM or the repo. Make the pair with
# `age-keygen -o key.txt` and keep key.txt in a password manager and on paper; anyone
# without it cannot open a backup, and neither can you.
set -euo pipefail

usage="usage: deploy/setup-backup.sh <user@vm> <age public key> [ssh options...]
       deploy/setup-backup.sh <user@vm> --finish <known_hosts file> [ssh options...]"
host=${1:-}
[ -n "$host" ] && [[ $host == *@* ]] && [[ $host != -* ]] || { echo "$usage" >&2; exit 2; }
shift

here=$(cd "$(dirname "$0")" && pwd)
local_dir=${BACKUP_LOCAL_DIR:-$here/../target/backup}

# Sends a file inside the VM's half, between quoted markers, unchanged.
embed() {
  printf "cat > %s <<'BF_BACKUP_FILE_END'\n" "$2"
  cat "$1"
  printf 'BF_BACKUP_FILE_END\n'
}

if [ "${1:-}" = --finish ]; then
  known_file=${2:?$usage}
  shift 2
  [ -f "$known_file" ] || { echo "there is no known_hosts file at $known_file" >&2; exit 2; }
  lines=()
  ips=()
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    if [[ $line =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\ ssh-ed25519\ [A-Za-z0-9+/]+={0,2}$ ]]; then
      lines+=("$line")
      ips+=("${BASH_REMATCH[1]}")
    else
      echo "$known_file has a line that is not '<IPv4> ssh-ed25519 <key>': $line" >&2
      exit 2
    fi
  done < "$known_file"
  [ "${#lines[@]}" -gt 0 ] || { echo "$known_file names no node" >&2; exit 2; }

  remote() {
    echo 'set -eu'
    printf 'known=(\n'; printf "  '%s'\n" "${lines[@]}"; printf ')\n'
    printf 'ips=('; printf " '%s'" "${ips[@]}"; printf ' )\n'
    cat <<'REMOTE'
for f in /etc/barely-free/backup-ssh/id_ed25519 /etc/barely-free/backup.recipients /usr/local/lib/barely-free/bf-backup.sh; do
  if [ ! -e "$f" ]; then
    echo "$f is missing: run the first step (deploy/setup-backup.sh <vm> <age public key>) first" >&2
    exit 2
  fi
done
umask 022
printf '%s\n' "${known[@]}" > /etc/barely-free/backup-ssh/known_hosts.new
chmod 0644 /etc/barely-free/backup-ssh/known_hosts.new
chown root:root /etc/barely-free/backup-ssh/known_hosts.new
mv -f /etc/barely-free/backup-ssh/known_hosts.new /etc/barely-free/backup-ssh/known_hosts
printf 'bf-backup@%s\n' "${ips[@]}" > /etc/barely-free/backup-targets.new
chmod 0644 /etc/barely-free/backup-targets.new
chown root:root /etc/barely-free/backup-targets.new
mv -f /etc/barely-free/backup-targets.new /etc/barely-free/backup-targets

echo "running one backup now..."
code=0
systemctl start bf-backup.service || code=$?
cat /var/lib/barely-free/backup-status 2>/dev/null || echo "(no status file)"
systemctl enable --now bf-backup.timer
if [ "$code" -ne 0 ]; then
  echo "the first backup failed; see the status above and: journalctl -u bf-backup" >&2
  exit 1
fi
echo "the first backup worked, and the nightly timer is on"
REMOTE
  }
  remote | ssh "$@" "$host" 'bash -s'
  exit
fi

recipient=${1:-}
shift || true
if [[ ! $recipient =~ ^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$ ]]; then
  echo "that is not an age public key (age1 and 58 more letters and digits): '$recipient'" >&2
  echo "$usage" >&2
  exit 2
fi

remote() {
  echo 'set -eu'
  printf "recipient='%s'\n" "$recipient"
  echo 'umask 022'
  echo 'install -d -m 0755 /usr/local/lib/barely-free'
  embed "$here/bf-backup.sh" /usr/local/lib/barely-free/bf-backup.sh.new
  embed "$here/bf-backup.service" /etc/systemd/system/bf-backup.service.new
  embed "$here/bf-backup.timer" /etc/systemd/system/bf-backup.timer.new
  cat <<'REMOTE'
if ! command -v age >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y age >/dev/null
fi
chmod 0755 /usr/local/lib/barely-free/bf-backup.sh.new
chown root:root /usr/local/lib/barely-free/bf-backup.sh.new
mv -f /usr/local/lib/barely-free/bf-backup.sh.new /usr/local/lib/barely-free/bf-backup.sh
for unit in bf-backup.service bf-backup.timer; do
  chmod 0644 "/etc/systemd/system/$unit.new"
  mv -f "/etc/systemd/system/$unit.new" "/etc/systemd/system/$unit"
done
systemctl daemon-reload

install -d -m 0700 -o barely-free -g barely-free /etc/barely-free/backup-ssh
if [ ! -f /etc/barely-free/backup-ssh/id_ed25519 ]; then
  runuser -u barely-free -- ssh-keygen -q -t ed25519 -N '' -C barely-free-backup \
    -f /etc/barely-free/backup-ssh/id_ed25519
fi

printf '# The backups are encrypted to this key. The VM can lock a backup, never open one.\n%s\n' \
  "$recipient" > /etc/barely-free/backup.recipients.new
chmod 0644 /etc/barely-free/backup.recipients.new
chown root:root /etc/barely-free/backup.recipients.new
mv -f /etc/barely-free/backup.recipients.new /etc/barely-free/backup.recipients

echo "PUBKEY $(cat /etc/barely-free/backup-ssh/id_ed25519.pub)"
REMOTE
}

said=$(remote | ssh "$@" "$host" 'bash -s')
read -r key_type key_b64 _ <<< "$(printf '%s\n' "$said" | sed -n 's/^PUBKEY //p')"
if [ "$key_type" != ssh-ed25519 ] || [[ ! $key_b64 =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; then
  echo "the VM did not give back its backup key" >&2
  exit 1
fi
mkdir -p "$local_dir"
echo "ssh-ed25519 $key_b64 barely-free-backup" > "$local_dir/vm-backup-key.pub"
echo "the VM is ready; its backup key is in $local_dir/vm-backup-key.pub"
echo "next: deploy/node-backup-receiver.sh root@<node ip> $local_dir/vm-backup-key.pub <ssh options>, for each node"

#!/bin/bash
# Lets a node keep the web VM's nightly backups. Spec: specs/backup.md.
#
# Run it yourself, once per node, after `deploy/setup-backup.sh root@<vm> <age key>` has
# saved the VM's backup key to target/backup/vm-backup-key.pub:
#   deploy/node-backup-receiver.sh root@<node ip> target/backup/vm-backup-key.pub -i ~/.ssh/<key> -o IdentitiesOnly=yes
#
# On the node it:
#   - makes the user bf-backup (shell /bin/sh, which sshd needs to run the forced command;
#     its password is locked, so the one key below is the only way in);
#   - installs deploy/bf-backup-receive as /usr/local/bin/bf-backup-receive (root's, 0755);
#   - makes /var/lib/bf-backup (bf-backup's, 0700), where the encrypted backups are kept;
#   - writes ~bf-backup/.ssh/authorized_keys (root's, 0644, in a root-owned .ssh) with the
#     VM's key pinned to the receiver:
#       restrict,command="/usr/local/bin/bf-backup-receive" ssh-ed25519 AAAA... barely-free-backup
#     so the key can only add a new file: no shell, no forwarding, no reading or deleting;
#   - checks that sshd lets bf-backup in (AllowUsers/AllowGroups/DenyUsers), and exits 2
#     with what to change if not; it does not edit sshd's settings itself.
# Then it adds the node's ed25519 host key to target/backup/known_hosts on this Mac, which
# `deploy/setup-backup.sh root@<vm> --finish target/backup/known_hosts` installs on the VM,
# so the VM only ever talks to the real node. Safe to run again: the user is made once, the
# key and the receiver are replaced, the host key line is replaced.
set -euo pipefail

usage="usage: deploy/node-backup-receiver.sh <user@node ip> <vm backup public key file> [ssh options...]"
host=${1:?$usage}
key_file=${2:?$usage}
shift 2

if [[ ! $host =~ ^[a-z_][a-z0-9_-]*@([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$ ]]; then
  echo "the node must be given as user@<IPv4 address> (the address goes into known_hosts), not: $host" >&2
  exit 2
fi
ip=${BASH_REMATCH[1]}

[ -f "$key_file" ] || { echo "there is no key file at $key_file" >&2; exit 2; }
lines=$(grep -c . "$key_file" || true)
[ "$lines" = 1 ] || { echo "$key_file must hold exactly one key, found $lines lines" >&2; exit 2; }
read -r key_type key_b64 _ < <(grep . "$key_file")
if [ "$key_type" != ssh-ed25519 ] || [[ ! $key_b64 =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; then
  echo "$key_file is not one plain ssh-ed25519 public key" >&2
  exit 2
fi

here=$(cd "$(dirname "$0")" && pwd)
local_dir=${BACKUP_LOCAL_DIR:-$here/../target/backup}

# The node's half: the receiver travels inside it, between quoted markers, unchanged.
remote() {
  printf 'set -eu\nkey_type=%s\nkey_b64=%s\n' "$key_type" "$key_b64"
  printf "cat > /usr/local/bin/bf-backup-receive.new <<'BF_BACKUP_RECEIVE_END'\n"
  cat "$here/bf-backup-receive"
  printf 'BF_BACKUP_RECEIVE_END\n'
  cat <<'REMOTE'
umask 022
if ! id bf-backup >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /home/bf-backup --shell /bin/sh bf-backup
fi
passwd -l bf-backup >/dev/null

chmod 0755 /usr/local/bin/bf-backup-receive.new
chown root:root /usr/local/bin/bf-backup-receive.new
mv -f /usr/local/bin/bf-backup-receive.new /usr/local/bin/bf-backup-receive

install -d -m 0700 -o bf-backup -g bf-backup /var/lib/bf-backup
install -d -m 0755 -o root -g root /home/bf-backup/.ssh
printf 'restrict,command="/usr/local/bin/bf-backup-receive" %s %s barely-free-backup\n' \
  "$key_type" "$key_b64" > /home/bf-backup/.ssh/authorized_keys.new
chmod 0644 /home/bf-backup/.ssh/authorized_keys.new
chown root:root /home/bf-backup/.ssh/authorized_keys.new
mv -f /home/bf-backup/.ssh/authorized_keys.new /home/bf-backup/.ssh/authorized_keys

settings=$(sshd -T -C user=bf-backup,host=backup,addr=192.0.2.1 2>&1) || {
  echo "cannot read sshd's settings: $settings" >&2
  exit 1
}
# `sshd -T` prints one line per entry: "allowusers root", "allowusers lao", ...
entries() {
  printf '%s\n' "$settings" | awk -v key="$1" '$1 == key { for (i = 2; i <= NF; i++) print $i }'
}
blocked=""
allow_users=$(entries allowusers)
if [ -n "$allow_users" ] && ! printf '%s\n' "$allow_users" | grep -qx bf-backup; then
  blocked="AllowUsers lets in only $(printf '%s\n' "$allow_users" | tr '\n' ' ')"
fi
allow_groups=$(entries allowgroups)
if [ -n "$allow_groups" ]; then
  blocked="AllowGroups is set ($(printf '%s\n' "$allow_groups" | tr '\n' ' '))"
fi
if entries denyusers | grep -qx bf-backup; then
  blocked="DenyUsers names bf-backup"
fi
if [ -n "$blocked" ]; then
  echo "sshd would keep bf-backup out: $blocked. Let bf-backup in (for example add it to AllowUsers), reload ssh and run this again." >&2
  exit 2
fi

echo "HOSTKEY $(cat /etc/ssh/ssh_host_ed25519_key.pub)"
REMOTE
}

code=0
said=$(remote | ssh "$@" "$host" 'sh -s') || code=$?
if [ "$code" -ne 0 ]; then
  exit "$code"
fi

hostkey=$(printf '%s\n' "$said" | sed -n 's/^HOSTKEY //p')
read -r host_type host_b64 _ <<< "$hostkey"
if [ "$host_type" != ssh-ed25519 ] || [[ ! $host_b64 =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; then
  echo "the node did not give back its ed25519 host key" >&2
  exit 1
fi

mkdir -p "$local_dir"
known="$local_dir/known_hosts"
touch "$known"
{ grep -v "^$ip " "$known" || true; echo "$ip ssh-ed25519 $host_b64"; } > "$known.new"
mv -f "$known.new" "$known"
echo "node $ip keeps the VM's backups; its host key is in $known"

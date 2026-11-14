#!/bin/bash
# Gets the accounts database back from the nightly backups. Spec: specs/backup.md.
# Run it yourself on the Mac; it needs age (`brew install age`) and your age secret key.
#
#   deploy/restore-backup.sh fetch root@<node ip> <age secret key file> -i ~/.ssh/<key> -o IdentitiesOnly=yes
#     Takes the newest backup from the node, decrypts it, unpacks it into
#     target/restore/control-<time>/ (only you can open it), checks every SHA-256 sum in its
#     manifest and the database's own integrity check, and says what is in it. It changes
#     nothing on any server: this is the restore drill. Delete the folder when done; it
#     holds the database and the fingerprint key in the clear.
#
#   deploy/restore-backup.sh put root@<vm ip> target/restore/control-<time> -o Port=2222
#     Puts that backup on the web VM: checks the sums again (here and there), stops
#     bf-control, keeps the current database and key as *.before-restore-<time>, puts the
#     backup's in place (barely-free's, 0600), starts bf-control again and runs
#     `bf-control node check` for every node. A node that holds a newer list than the
#     restored database is shown as AHEAD with the `bf-control list raise <n>` to run;
#     until then that node refuses new lists. Everything since the backup is gone.
set -euo pipefail

usage="usage: deploy/restore-backup.sh fetch <user@node> <age secret key file> [ssh options...]
       deploy/restore-backup.sh put <user@vm> <restored folder> [ssh options...]"
here=$(cd "$(dirname "$0")" && pwd)
local_dir=${BACKUP_LOCAL_DIR:-$here/../target/restore}

fail() {
  echo "restore-backup: $*" >&2
  exit 1
}

sum256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# check_manifest FOLDER: the manifest's time matches the folder's name and every sum matches.
check_manifest() {
  local dir=$1 stem want have f
  stem=$(basename "$dir")
  [ -f "$dir/manifest" ] || { echo "restore-backup: $dir has no manifest" >&2; return 1; }
  if [ "$(head -n 1 "$dir/manifest")" != "made=${stem#control-}" ]; then
    echo "restore-backup: the manifest's time is not ${stem#control-}" >&2
    return 1
  fi
  for f in control.db control.key; do
    want=$(awk -v f="$f" '$1 == "sha256" && $3 == f { print $2 }' "$dir/manifest")
    [ -f "$dir/$f" ] && have=$(sum256 "$dir/$f") || have=""
    if [ -z "$want" ] || [ "$want" != "$have" ]; then
      echo "restore-backup: the sum of $f does not match the manifest" >&2
      return 1
    fi
  done
}

fetch() {
  local host=${1:?$usage} identity=${2:?$usage}
  shift 2
  command -v age >/dev/null 2>&1 || { echo "age is not installed on this Mac: brew install age" >&2; exit 2; }
  [ -f "$identity" ] || { echo "there is no age secret key file at $identity" >&2; exit 2; }

  local newest stem out members
  newest=$(ssh "$@" "$host" 'ls -1 /var/lib/bf-backup' \
    | grep -E '^control-[0-9]{8}T[0-9]{6}Z\.tar\.age$' | sort | tail -n 1 || true)
  [ -n "$newest" ] || fail "there is no backup on $host"
  stem=${newest%.tar.age}
  out="$local_dir/$stem"
  mkdir -p "$local_dir"
  rm -rf -- "$out"
  (umask 077 && mkdir "$out")

  ssh "$@" "$host" "cat /var/lib/bf-backup/$newest" > "$out/$newest"
  # From here, a failure must not leave anything in the clear.
  trap 'rm -f -- "$out/backup.tar" "$out/manifest" "$out/control.db" "$out/control.key"' ERR
  (umask 077 && age -d -i "$identity" -o "$out/backup.tar" "$out/$newest") \
    || fail "$newest cannot be decrypted with that key"
  members=$(tar -tf "$out/backup.tar" | sort | tr '\n' ' ')
  if [ "$members" != "control.db control.key manifest " ]; then
    fail "$newest holds something other than manifest, control.db and control.key: $members"
  fi
  (umask 077 && tar -xf "$out/backup.tar" -C "$out" manifest control.db control.key)
  rm -f -- "$out/backup.tar"
  check_manifest "$out" || fail "$newest does not match its own manifest"

  local integrity version accounts devices
  integrity=$(sqlite3 "$out/control.db" 'PRAGMA integrity_check' 2>&1 | head -n 1)
  [ "$integrity" = ok ] || fail "the database did not pass its check: $integrity"
  version=$(sqlite3 "$out/control.db" 'PRAGMA user_version')
  accounts=$(sqlite3 "$out/control.db" 'SELECT count(*) FROM accounts')
  devices=$(sqlite3 "$out/control.db" 'SELECT count(*) FROM devices WHERE removed_at IS NULL')
  trap - ERR
  echo "$newest from $host: schema version $version, $accounts accounts, $devices devices, integrity ok"
  echo "unpacked in $out (the database and the key in the clear: delete it when done)"
}

put() {
  local host=${1:?$usage} folder=${2:?$usage}
  shift 2
  [ -d "$folder" ] || fail "there is no folder $folder"
  check_manifest "$folder" || fail "$folder does not match its manifest; fetch it again"

  tar -C "$folder" -cf - manifest control.db control.key \
    | ssh "$@" "$host" 'umask 077; rm -rf /root/bf-restore && mkdir /root/bf-restore && tar -xf - -C /root/bf-restore'
  ssh "$@" "$host" 'bash -s' <<'REMOTE'
set -eu
stage=/root/bf-restore
cd "$stage"
for f in control.db control.key; do
  want=$(awk -v f="$f" '$1 == "sha256" && $3 == f { print $2 }' manifest)
  have=$(sha256sum "$f" | cut -d' ' -f1)
  if [ -z "$want" ] || [ "$want" != "$have" ]; then
    echo "restore-backup: $f changed on the way; nothing was touched" >&2
    exit 1
  fi
done

systemctl stop bf-control
stamp=$(date -u +%Y%m%dT%H%M%SZ)
db=/var/lib/barely-free/control.db
key=/etc/barely-free/control.key
if [ -e "$db" ]; then cp -p "$db" "$db.before-restore-$stamp"; fi
for side in -journal -wal -shm; do
  if [ -e "$db$side" ]; then mv "$db$side" "$db.before-restore-$stamp$side"; fi
done
if [ -e "$key" ]; then cp -p "$key" "$key.before-restore-$stamp"; fi
install -m 0600 control.db "$db.new"
chown barely-free:barely-free "$db.new"
mv -f "$db.new" "$db"
install -m 0600 control.key "$key.new"
chown barely-free:barely-free "$key.new"
mv -f "$key.new" "$key"
cd /
rm -rf "$stage"
systemctl start bf-control
echo "restored; the database and key before it are kept as *.before-restore-$stamp"

for node in $(runuser -u barely-free -- bf-control node list | awk '{ print $1 }'); do
  runuser -u barely-free -- bf-control node check "$node" || true
done
echo "if a node above is AHEAD, run the 'bf-control list raise <n>' it names, as barely-free"
REMOTE
}

action=${1:-}
shift || true
case $action in
  fetch) fetch "$@" ;;
  put) put "$@" ;;
  *) echo "$usage" >&2; exit 2 ;;
esac

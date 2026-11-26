#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

usage() {
  cat <<'EOF'
Usage: restore-vault-server.sh [options] <archive.tar.gz>
       restore-vault-server.sh [options]  # restore latest archive from ./backups

Restore a vault-server backup into a clean data directory.

Options:
  -d, --data-dir PATH       Restore destination (default: /data)
      --replace             Replace an existing non-empty destination
  -h, --help                Show this help
EOF
}

ARCHIVE=""
DATA_DIR="/data"
REPLACE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--data-dir)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      DATA_DIR=$2
      shift 2
      ;;
    --replace)
      REPLACE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ -n "$ARCHIVE" ]]; then
        echo "Unexpected argument: $1" >&2
        usage >&2
        exit 2
      fi
      ARCHIVE=$1
      shift
      ;;
  esac
done

if [[ -z "$ARCHIVE" ]]; then
  BACKUP_DIR="$ROOT_DIR/backups"
  if [[ -d "$BACKUP_DIR" ]]; then
    latest=""
    for candidate in "$BACKUP_DIR"/vault-server-backup-*.tar.gz; do
      [[ -f "$candidate" ]] || continue
      if [[ -z "$latest" || "$candidate" -nt "$latest" ]]; then
        latest=$candidate
      fi
    done
    ARCHIVE=$latest
  fi
  if [[ -z "$ARCHIVE" ]]; then
    echo "No backup archive specified and no vault-server backup found in $ROOT_DIR/backups" >&2
    usage >&2
    exit 2
  fi
fi
if [[ "$ARCHIVE" != /* ]]; then
  ARCHIVE="$ROOT_DIR/$ARCHIVE"
fi
if [[ "$DATA_DIR" != /* ]]; then
  DATA_DIR="$ROOT_DIR/$DATA_DIR"
fi
if [[ ! -f "$ARCHIVE" ]]; then
  echo "Backup archive not found: $ARCHIVE" >&2
  exit 1
fi

python3 - "$ARCHIVE" <<'PY'
import sys
import tarfile

archive_path = sys.argv[1]
try:
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
except (OSError, tarfile.TarError) as error:
    raise SystemExit(f"Invalid backup archive: {error}")

seen = set()
for member in members:
    name = member.name
    parts = name.rstrip("/").split("/")
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or any(part in ("", ".", "..") for part in parts)
        or parts[0] != "vault-server"
        or name in seen
        or not (member.isdir() or member.isfile())
    ):
        raise SystemExit(f"Invalid or unsafe archive entry: {name!r}")
    seen.add(name)

if "vault-server/manifest.txt" not in seen:
    raise SystemExit("Invalid backup archive: manifest.txt not found")
if not any(name.startswith("vault-server/data/") for name in seen) and not any(
    name.startswith("vault-server/database/") for name in seen
):
    raise SystemExit("Invalid backup archive: no server data found")
PY

if [[ -e "$DATA_DIR" ]] && [[ -n "$(find "$DATA_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]] && [[ "$REPLACE" != true ]]; then
  echo "Restore destination is not empty: $DATA_DIR" >&2
  echo "Use --replace to confirm replacement" >&2
  exit 1
fi

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

tar -xzf "$ARCHIVE" -C "$STAGING"
RESTORE_ROOT="$STAGING/vault-server"

if [[ ! -d "$RESTORE_ROOT" ]]; then
  echo "Invalid backup archive: vault-server directory not found" >&2
  exit 1
fi
if ! (cd "$RESTORE_ROOT" && sha256sum -c manifest.txt >/dev/null); then
  echo "Backup checksum verification failed" >&2
  exit 1
fi

if [[ -d "$RESTORE_ROOT/data" ]]; then
  if [[ -z "$(find "$RESTORE_ROOT/data" -type f -print -quit)" ]]; then
    echo "Invalid backup archive: data directory contains no files" >&2
    exit 1
  fi
else
  for required in vault.db vault.db.key vault-secrets.db vault-secrets.db.key; do
    if [[ ! -f "$RESTORE_ROOT/database/$required" ]]; then
      echo "Invalid backup archive: database/$required not found" >&2
      exit 1
    fi
  done
fi

mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

if [[ "$REPLACE" == true ]]; then
  find "$DATA_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi

if [[ -d "$RESTORE_ROOT/data" ]]; then
  cp -a "$RESTORE_ROOT/data/." "$DATA_DIR/"
  find "$DATA_DIR" -type d -exec chmod 700 {} +
  find "$DATA_DIR" -type f -exec chmod 600 {} +
else
  install -m 600 "$RESTORE_ROOT/database/vault.db" "$DATA_DIR/vault.db"
  install -m 600 "$RESTORE_ROOT/database/vault.db.key" "$DATA_DIR/vault.db.key"
  install -m 600 "$RESTORE_ROOT/database/vault-secrets.db" "$DATA_DIR/vault-secrets.db"
  install -m 600 "$RESTORE_ROOT/database/vault-secrets.db.key" "$DATA_DIR/vault-secrets.db.key"

  if [[ -f "$RESTORE_ROOT/database/vault.db-wal" ]]; then
    install -m 600 "$RESTORE_ROOT/database/vault.db-wal" "$DATA_DIR/vault.db-wal"
  fi
  if [[ -f "$RESTORE_ROOT/database/vault.db-shm" ]]; then
    install -m 600 "$RESTORE_ROOT/database/vault.db-shm" "$DATA_DIR/vault.db-shm"
  fi
  if [[ -f "$RESTORE_ROOT/database/vault-secrets.db-wal" ]]; then
    install -m 600 "$RESTORE_ROOT/database/vault-secrets.db-wal" "$DATA_DIR/vault-secrets.db-wal"
  fi
  if [[ -f "$RESTORE_ROOT/database/vault-secrets.db-shm" ]]; then
    install -m 600 "$RESTORE_ROOT/database/vault-secrets.db-shm" "$DATA_DIR/vault-secrets.db-shm"
  fi
  if [[ -f "$RESTORE_ROOT/database/audit.db" ]]; then
    install -m 600 "$RESTORE_ROOT/database/audit.db" "$DATA_DIR/audit.db"
  fi
  if [[ -f "$RESTORE_ROOT/database/audit.db-wal" ]]; then
    install -m 600 "$RESTORE_ROOT/database/audit.db-wal" "$DATA_DIR/audit.db-wal"
  fi
  if [[ -f "$RESTORE_ROOT/database/audit.db-shm" ]]; then
    install -m 600 "$RESTORE_ROOT/database/audit.db-shm" "$DATA_DIR/audit.db-shm"
  fi
  for annual_db in "$RESTORE_ROOT"/database/*-????.*; do
    [[ -f "$annual_db" ]] || continue
    [[ "$annual_db" != *-wal && "$annual_db" != *-shm ]] || continue
    annual_name=$(basename "$annual_db")
    install -m 600 "$annual_db" "$DATA_DIR/$annual_name"
    if [[ -f "${annual_db}-wal" ]]; then
      install -m 600 "${annual_db}-wal" "$DATA_DIR/${annual_name}-wal"
    fi
    if [[ -f "${annual_db}-shm" ]]; then
      install -m 600 "${annual_db}-shm" "$DATA_DIR/${annual_name}-shm"
    fi
  done

  mkdir -p "$DATA_DIR/tls"
  chmod 700 "$DATA_DIR/tls"
  if [[ -f "$RESTORE_ROOT/tls/server.crt" ]]; then
    install -m 600 "$RESTORE_ROOT/tls/server.crt" "$DATA_DIR/tls/server.crt"
  fi
  if [[ -f "$RESTORE_ROOT/tls/server.key" ]]; then
    install -m 600 "$RESTORE_ROOT/tls/server.key" "$DATA_DIR/tls/server.key"
  fi
  if [[ -f "$RESTORE_ROOT/tls/client-ca.crt" ]]; then
    install -m 600 "$RESTORE_ROOT/tls/client-ca.crt" "$DATA_DIR/tls/client-ca.crt"
  fi
  if [[ -f "$RESTORE_ROOT/config/.env" ]]; then
    install -m 600 "$RESTORE_ROOT/config/.env" "$DATA_DIR/server.env"
  fi
fi

cat <<EOF
Vault server state restored to $DATA_DIR

Next:
  VAULT_SERVER_DB_PASSWORD='<database password>' \
  ./bin/vault-server \
    --env-file $DATA_DIR/server.env \
    --db $DATA_DIR/vault.db \
    --secrets-db $DATA_DIR/vault-secrets.db
EOF

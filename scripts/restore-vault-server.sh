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
if [[ ! -f "$RESTORE_ROOT/manifest.txt" ]]; then
  echo "Invalid backup archive: manifest.txt not found" >&2
  exit 1
fi
if [[ ! -f "$RESTORE_ROOT/database/vault.db" ]]; then
  echo "Invalid backup archive: database/vault.db not found" >&2
  exit 1
fi
if [[ ! -f "$RESTORE_ROOT/database/vault.db.key" ]]; then
  echo "Invalid backup archive: password-protected database key not found" >&2
  exit 1
fi

if ! (cd "$RESTORE_ROOT" && sha256sum -c manifest.txt >/dev/null); then
  echo "Backup checksum verification failed" >&2
  exit 1
fi

mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

if [[ "$REPLACE" == true ]]; then
  find "$DATA_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi

install -m 600 "$RESTORE_ROOT/database/vault.db" "$DATA_DIR/vault.db"
install -m 600 "$RESTORE_ROOT/database/vault.db.key" "$DATA_DIR/vault.db.key"

if [[ -f "$RESTORE_ROOT/database/vault.db-wal" ]]; then
  install -m 600 "$RESTORE_ROOT/database/vault.db-wal" "$DATA_DIR/vault.db-wal"
fi
if [[ -f "$RESTORE_ROOT/database/vault.db-shm" ]]; then
  install -m 600 "$RESTORE_ROOT/database/vault.db-shm" "$DATA_DIR/vault.db-shm"
fi

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

cat <<EOF
Vault server state restored to $DATA_DIR

Next:
  VAULT_SERVER_DB_PASSWORD='<database password>' \
  ./bin/vault-server \
    --env-file $DATA_DIR/server.env \
    --db $DATA_DIR/vault.db
EOF

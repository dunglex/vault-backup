#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

usage() {
  cat <<'EOF'
Usage: backup-vault-server.sh [options]

Options:
  -o, --output PATH         Archive path (default: ./backups/vault-server-backup-YYYYMMDD-HHMMSS.tar.gz)
      --db PATH             SQLite database path (default: VAULT_SERVER_DB or tests/data/vault.db)
      --secrets-db PATH     Encrypted secrets database path (default: alongside app database)
      --audit-db PATH       Audit database path (default: alongside the main database as audit.db)
      --env-file PATH       Server .env file to include (default: VAULT_SERVER_ENV_FILE or ./.env)
      --tls-cert PATH       Server TLS certificate (default: VAULT_SERVER_TLS_CERT)
      --tls-key PATH        Server TLS private key (default: VAULT_SERVER_TLS_KEY)
      --mtls-ca-cert PATH   mTLS client CA (default: VAULT_SERVER_MTLS_CA_CERT)
  -h, --help                Show this help
EOF
}

TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
mkdir -p "$ROOT_DIR/backups"
OUTPUT="${ROOT_DIR}/backups/vault-server-backup-${TIMESTAMP}.tar.gz"
DB_PATH="${VAULT_SERVER_DB:-$SCRIPT_DIR/data/vault.db}"
SECRETS_DB_PATH="${VAULT_SERVER_SECRETS_DB:-}"
ENV_FILE="${VAULT_SERVER_ENV_FILE:-$ROOT_DIR/.env}"
TLS_CERT="${VAULT_SERVER_TLS_CERT:-}"
TLS_KEY="${VAULT_SERVER_TLS_KEY:-}"
MTLS_CA_CERT="${VAULT_SERVER_MTLS_CA_CERT:-}"
AUDIT_DB_PATH="${VAULT_SERVER_AUDIT_DB:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      OUTPUT=$2
      shift 2
      ;;
    --db)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      DB_PATH=$2
      shift 2
      ;;
    --secrets-db)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      SECRETS_DB_PATH=$2
      shift 2
      ;;
    --audit-db)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      AUDIT_DB_PATH=$2
      shift 2
      ;;
    --env-file)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      ENV_FILE=$2
      shift 2
      ;;
    --tls-cert)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      TLS_CERT=$2
      shift 2
      ;;
    --tls-key)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      TLS_KEY=$2
      shift 2
      ;;
    --mtls-ca-cert)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      MTLS_CA_CERT=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$DB_PATH" != /* ]]; then
  DB_PATH="$ROOT_DIR/$DB_PATH"
fi
if [[ -z "$SECRETS_DB_PATH" ]]; then
  DB_NAME=$(basename "$DB_PATH")
  DB_EXTENSION="${DB_NAME##*.}"
  if [[ "$DB_EXTENSION" == "$DB_NAME" ]]; then
    SECRETS_DB_NAME="${DB_NAME}-secrets"
  else
    SECRETS_DB_NAME="${DB_NAME%.*}-secrets.${DB_EXTENSION}"
  fi
  SECRETS_DB_PATH="$(dirname "$DB_PATH")/$SECRETS_DB_NAME"
elif [[ "$SECRETS_DB_PATH" != /* ]]; then
  SECRETS_DB_PATH="$ROOT_DIR/$SECRETS_DB_PATH"
fi
if [[ -z "$AUDIT_DB_PATH" ]]; then
  AUDIT_DB_PATH="$(dirname "$DB_PATH")/audit.db"
elif [[ "$AUDIT_DB_PATH" != /* ]]; then
  AUDIT_DB_PATH="$ROOT_DIR/$AUDIT_DB_PATH"
fi
if [[ "$ENV_FILE" != /* && -n "$ENV_FILE" ]]; then
  ENV_FILE="$ROOT_DIR/$ENV_FILE"
fi
for path_var in TLS_CERT TLS_KEY MTLS_CA_CERT; do
  path_value=${!path_var}
  if [[ -n "$path_value" && "$path_value" != /* ]]; then
    printf -v "$path_var" '%s' "$ROOT_DIR/$path_value"
  fi
done
if [[ "$OUTPUT" != /* ]]; then
  OUTPUT="$ROOT_DIR/$OUTPUT"
fi

if [[ ! -f "$DB_PATH" ]]; then
  echo "Database file not found: $DB_PATH" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
STAGING=$(mktemp -d)
ARCHIVE_DIR="$STAGING/vault-server"
mkdir -m 700 "$ARCHIVE_DIR"
trap 'rm -rf "$STAGING"' EXIT

copy_file() {
  local source=$1
  local category=$2
  local name=$3

  if [[ -f "$source" ]]; then
    mkdir -p "$ARCHIVE_DIR/$category"
    cp --preserve=mode,timestamps "$source" "$ARCHIVE_DIR/$category/$name"
    chmod 600 "$ARCHIVE_DIR/$category/$name"
  fi
}

copy_file "$DB_PATH" "database" "vault.db"
copy_file "${DB_PATH}-wal" "database" "vault.db-wal"
copy_file "${DB_PATH}-shm" "database" "vault.db-shm"
copy_file "${DB_PATH}.key" "database" "vault.db.key"
copy_file "$SECRETS_DB_PATH" "database" "vault-secrets.db"
copy_file "${SECRETS_DB_PATH}-wal" "database" "vault-secrets.db-wal"
copy_file "${SECRETS_DB_PATH}-shm" "database" "vault-secrets.db-shm"
copy_file "${SECRETS_DB_PATH}.key" "database" "vault-secrets.db.key"
copy_file "$AUDIT_DB_PATH" "database" "audit.db"
copy_file "${AUDIT_DB_PATH}-wal" "database" "audit.db-wal"
copy_file "${AUDIT_DB_PATH}-shm" "database" "audit.db-shm"
AUDIT_EXTENSION="${AUDIT_DB_PATH##*.}"
AUDIT_STEM="${AUDIT_DB_PATH%.*}"
AUDIT_BASENAME=$(basename "$AUDIT_STEM")
for annual_db in "${AUDIT_STEM}"-????."${AUDIT_EXTENSION}"; do
  [[ -f "$annual_db" ]] || continue
  annual_name=$(basename "$annual_db")
  copy_file "$annual_db" "database" "$annual_name"
  copy_file "${annual_db}-wal" "database" "${annual_name}-wal"
  copy_file "${annual_db}-shm" "database" "${annual_name}-shm"
done
copy_file "$TLS_CERT" "tls" "server.crt"
copy_file "$TLS_KEY" "tls" "server.key"
copy_file "$MTLS_CA_CERT" "tls" "client-ca.crt"
copy_file "$ENV_FILE" "config" ".env"

if [[ ! -f "$ARCHIVE_DIR/database/vault.db.key" ]]; then
  echo "Protected database key not found: ${DB_PATH}.key" >&2
  exit 1
fi
if [[ ! -f "$ARCHIVE_DIR/database/vault-secrets.db" || ! -f "$ARCHIVE_DIR/database/vault-secrets.db.key" ]]; then
  echo "Encrypted secrets database or protected key not found: $SECRETS_DB_PATH" >&2
  exit 1
fi
if [[ ! -f "$ARCHIVE_DIR/database/audit.db" ]] && ! compgen -G "$ARCHIVE_DIR/database/${AUDIT_BASENAME}-????.${AUDIT_EXTENSION}" >/dev/null; then
  echo "Audit database not found: $AUDIT_DB_PATH or its annual databases" >&2
  exit 1
fi

MANIFEST="$ARCHIVE_DIR/manifest.txt"
{
  echo "# Vault server backup"
  echo "# Created-UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Database: vault.db"
  echo "# Protected key: vault.db.key"
  echo "# Secrets database: vault-secrets.db"
  echo "# Secrets database protected key: vault-secrets.db.key"
  find "$ARCHIVE_DIR" -type f ! -name manifest.txt -printf '%P\n' | sort | while read -r file; do
    hash=$(sha256sum "$ARCHIVE_DIR/$file" | awk '{print $1}')
    printf '%s  %s\n' "$hash" "$file"
  done
} >"$MANIFEST"
chmod 600 "$MANIFEST"

tar -czf "$OUTPUT" -C "$STAGING" vault-server
chmod 600 "$OUTPUT"

echo "Vault server backup saved to $OUTPUT"
echo "Archive permissions: 600"

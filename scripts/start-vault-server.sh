#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DATA_DIR=$ROOT_DIR/data
BACKUP_DIR=$ROOT_DIR/backup

mkdir -p "$DATA_DIR" "$BACKUP_DIR"

VAULT_SERVER_DB=$DATA_DIR/vault.db
VAULT_SERVER_SECRETS_DB=$DATA_DIR/vault-secrets.db
TLS_CERT=$DATA_DIR/localhost.pem
TLS_KEY=$DATA_DIR/localhost-key.pem

if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
  MKCERT="$ROOT_DIR/bin/mkcert"
  if [[ ! -x "$MKCERT" ]]; then
    echo "bundled mkcert helper is not built; run ./scripts/build.sh first" >&2
    exit 1
  fi

  "$MKCERT" -cert-file "$TLS_CERT" -key-file "$TLS_KEY" localhost 127.0.0.1 ::1
fi

echo "Using Vault server DB at $VAULT_SERVER_DB"
echo "Using Vault server secrets DB at $VAULT_SERVER_SECRETS_DB"
echo "Using Vault server backups at $BACKUP_DIR"
echo "Using TLS certificate at $TLS_CERT"
VAULT_SERVER_DB_PASSWORD="${VAULT_SERVER_DB_PASSWORD:-local-development-password}" \
  VAULT_SERVER_BACKUP_DIR="$BACKUP_DIR" \
  exec "$ROOT_DIR/bin/vault-server" --db "$VAULT_SERVER_DB" --secrets-db "$VAULT_SERVER_SECRETS_DB" --http-addr "127.0.0.1:8201" --https-addr "127.0.0.1:8200" --tls-cert "$TLS_CERT" --tls-key "$TLS_KEY"
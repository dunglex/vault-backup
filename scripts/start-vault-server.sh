#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DATA_DIR=$SCRIPT_DIR/data
mkdir -p "$DATA_DIR"
VAULT_SERVER_DB=$DATA_DIR/vault.db
TLS_CERT=$DATA_DIR/localhost.pem
TLS_KEY=$DATA_DIR/localhost-key.pem

if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
  MKCERT="$SCRIPT_DIR/../bin/mkcert"
  if [[ ! -x "$MKCERT" ]]; then
    echo "bundled mkcert helper is not built; run ./scripts/build.sh first" >&2
    exit 1
  fi

  "$MKCERT" -cert-file "$TLS_CERT" -key-file "$TLS_KEY" localhost 127.0.0.1 ::1
fi

echo "Using Vault server DB at $VAULT_SERVER_DB"
echo "Using TLS certificate at $TLS_CERT"
VAULT_SERVER_DB_PASSWORD="${VAULT_SERVER_DB_PASSWORD:-local-development-password}" \
  exec "$SCRIPT_DIR/../bin/vault-server" --db "$VAULT_SERVER_DB" --tls-cert "$TLS_CERT" --tls-key "$TLS_KEY"
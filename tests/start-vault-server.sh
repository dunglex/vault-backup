#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DATA_DIR=$SCRIPT_DIR/data
mkdir -p "$DATA_DIR"
VAULT_SERVER_DB=$DATA_DIR/vault.db
TLS_CERT=$DATA_DIR/localhost.pem
TLS_KEY=$DATA_DIR/localhost-key.pem

if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
  if command -v mkcert >/dev/null 2>&1; then
    (cd "$DATA_DIR" && mkcert -cert-file localhost.pem -key-file localhost-key.pem localhost 127.0.0.1 ::1)
  else
    echo "mkcert is required: install it or run 'mkcert -install' first" >&2
    exit 1
  fi
fi

echo "Using Vault server DB at $VAULT_SERVER_DB"
echo "Using TLS certificate at $TLS_CERT"
exec "$SCRIPT_DIR/../bin/vault-server" --db "$VAULT_SERVER_DB" --tls-cert "$TLS_CERT" --tls-key "$TLS_KEY"
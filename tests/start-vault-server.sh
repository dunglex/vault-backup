#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DATA_DIR=$SCRIPT_DIR/data
mkdir -p "$DATA_DIR"
VAULT_SERVER_DB=$DATA_DIR/vault.db
echo "Using Vault server DB at $VAULT_SERVER_DB"
exec "$SCRIPT_DIR/../bin/vault-server" --db "$VAULT_SERVER_DB"
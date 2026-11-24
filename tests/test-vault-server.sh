#!/usr/bin/env bash
set -euo pipefail

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

"$TEST_DIR/test-vault-server-health.sh"
"$TEST_DIR/test-vault-server-auth.sh"
"$TEST_DIR/test-vault-server-secrets.sh"
"$TEST_DIR/test-vault-server-api.sh"
"$TEST_DIR/test-vault-server-storage.sh"

echo "All Vault server integration tests passed."

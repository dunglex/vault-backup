#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/test-vault-backup-common.sh"

build_backup_binaries
start_backup_server
setup_backup_account

set +e
INVALID_OUTPUT=$("$TMPDIR/vault-backup" \
  --url "$BASE_URL/api" \
  --token "managed-token" \
  --secret_name kv \
  --secret_path app/database \
  --output_mode invalid 2>&1)
INVALID_STATUS=$?
set -e
[[ "$INVALID_STATUS" -eq 2 ]] || fail "invalid configuration exited with $INVALID_STATUS, expected 2"
printf '%s' "$INVALID_OUTPUT" | grep -q 'output_mode must be one of' || fail "invalid configuration error was not reported"
echo "PASS: reject invalid CLI configuration before connecting"

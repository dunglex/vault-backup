#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/test-vault-backup-common.sh"

build_backup_binaries
start_backup_server
setup_backup_account
login_backup_account
create_backup_api_token

cat >"$TMPDIR/restored.env" <<'EOF'
DATABASE_HOST=restored.example.local
DATABASE_PORT=6432
DATABASE_USER=restored_admin
DATABASE_PASSWORD=restored-password
EOF

"$TMPDIR/vault-backup" \
  --url "$BASE_URL/api" --insecure \
  --token "$MANAGED_TOKEN" \
  --secret_name kv --secret_path app/restored \
  --restore --input_path "$TMPDIR/restored.env"

RESTORE_BODY=$(curl --insecure --silent --show-error --fail \
  -H "Authorization: Bearer $MANAGED_TOKEN" \
  "$BASE_URL/api/v1/kv/data/app/restored")
printf '%s' "$RESTORE_BODY" | grep -q 'restored.example.local' || fail "restore host missing"
printf '%s' "$RESTORE_BODY" | grep -q 'restored_admin' || fail "restore user missing"
printf '%s' "$RESTORE_BODY" | grep -q 'restored-password' || fail "restore password missing"
echo "PASS: env restore wrote secret to Vault"

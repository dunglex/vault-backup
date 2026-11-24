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

mkdir -p "$TMPDIR/restore-directory"
cat >"$TMPDIR/restore-directory/valid.env" <<'EOF'
VALUE=partial-restore-succeeded
EOF
printf '{invalid' >"$TMPDIR/restore-directory/invalid.json"

if "$TMPDIR/vault-backup" \
  --url "$BASE_URL/api" --insecure \
  --token "$MANAGED_TOKEN" \
  --secret_name kv --secret_path app/batch \
  --restore --input_path "$TMPDIR/restore-directory" \
  >"$TMPDIR/partial-restore.log" 2>&1; then
  fail "partial restore unexpectedly exited successfully"
fi
grep -q 'invalid.json' "$TMPDIR/partial-restore.log" || fail "partial restore did not report the failed file"

PARTIAL_BODY=$(curl --insecure --silent --show-error --fail \
  -H "Authorization: Bearer $MANAGED_TOKEN" \
  "$BASE_URL/api/v1/kv/data/app/batch/valid")
printf '%s' "$PARTIAL_BODY" | grep -q 'partial-restore-succeeded' || fail "successful file was not restored during partial operation"
echo "PASS: partial directory restore exited unsuccessfully"

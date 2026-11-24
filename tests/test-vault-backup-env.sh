#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/test-vault-backup-common.sh"

build_backup_binaries
start_backup_server
setup_backup_account
login_backup_account

PUT_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"data":{"DATABASE_HOST":"db.example.local","DATABASE_PORT":"5432","DATABASE_USER":"backup_admin","DATABASE_PASSWORD":"s3cr3t"}}' \
  -X PUT "$BASE_URL/api/v1/kv/data/app/database")
assert_status 200 "$PUT_STATUS" "seed KV v2 source secret"

"$TMPDIR/vault-backup" \
  --url "$BASE_URL/api" --insecure \
  --user "$USERNAME" --pass "$PASSWORD" \
  --secret_name kv --secret_path app/database \
  --output_mode file --output_format env --output_path "$TMPDIR/database.env"

[[ -f "$TMPDIR/database.env" ]] || fail "backup env file was not created"
tr -d '\r' <"$TMPDIR/database.env" >"$TMPDIR/database-normalized.env"
grep -q '^DATABASE_HOST=db.example.local$' "$TMPDIR/database-normalized.env" || fail "DATABASE_HOST missing from backup"
grep -q '^DATABASE_PORT=5432$' "$TMPDIR/database-normalized.env" || fail "DATABASE_PORT missing from backup"
grep -q '^DATABASE_USER=backup_admin$' "$TMPDIR/database-normalized.env" || fail "DATABASE_USER missing from backup"
grep -q '^DATABASE_PASSWORD=s3cr3t$' "$TMPDIR/database-normalized.env" || fail "DATABASE_PASSWORD missing from backup"
echo "PASS: Vault backup produced env file"

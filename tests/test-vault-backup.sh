#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMPDIR=$(mktemp -d)
SERVER_PID=""
PORT=18210
BASE_URL="http://127.0.0.1:$PORT"
SETUP_KEY="backup-test-setup-key"
USERNAME="admin"
PASSWORD="backup-test-password"

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_status() {
  local expected=$1
  local actual=$2
  local label=$3
  [[ "$actual" == "$expected" ]] || fail "$label: expected HTTP $expected, got $actual"
  echo "PASS: $label"
}

cd "$ROOT"
go build -o "$TMPDIR/vault-server" ./cmd/vault-server
go build -o "$TMPDIR/vault-backup" ./cmd/vault-backup

VAULT_SERVER_ADDR="127.0.0.1:$PORT" \
VAULT_SERVER_DB="$TMPDIR/vault.db" \
VAULT_SERVER_SETUP_KEY="$SETUP_KEY" \
"$TMPDIR/vault-server" >"$TMPDIR/server.log" 2>&1 &
SERVER_PID=$!

curl --fail --silent --retry 20 --retry-delay 1 --retry-connrefused \
  "$BASE_URL/health" >/dev/null

SETUP_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"setup_key":"backup-test-setup-key","username":"admin","password":"backup-test-password"}' \
  "$BASE_URL/v1/setup")
assert_status 201 "$SETUP_STATUS" "set up vault server"

LOGIN_BODY=$(curl --silent --show-error --fail \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"backup-test-password"}' \
  "$BASE_URL/v1/auth/login")
TOKEN=$(printf '%s' "$LOGIN_BODY" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[[ -n "$TOKEN" ]] || fail "obtain API token"

PUT_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"DATABASE_HOST":"db.example.local","DATABASE_PORT":"5432","DATABASE_USER":"backup_admin","DATABASE_PASSWORD":"s3cr3t"}}' \
  -X PUT "$BASE_URL/api/v1/kv/data/app/database")
assert_status 200 "$PUT_STATUS" "seed KV v2 source secret"

rm -f "$TMPDIR/database.env"
"$TMPDIR/vault-backup" \
  --url "$BASE_URL/api" \
  --user "$USERNAME" \
  --pass "$PASSWORD" \
  --secret_name kv \
  --secret_path app/database \
  --output_mode file \
  --output_format env \
  --output_path "$TMPDIR/database.env"

[[ -f "$TMPDIR/database.env" ]] || fail "backup env file was not created"
tr -d '\r' <"$TMPDIR/database.env" >"$TMPDIR/database-normalized.env"
grep -q '^DATABASE_HOST=db.example.local$' "$TMPDIR/database-normalized.env" || fail "DATABASE_HOST missing from backup"
grep -q '^DATABASE_PORT=5432$' "$TMPDIR/database-normalized.env" || fail "DATABASE_PORT missing from backup"
grep -q '^DATABASE_USER=backup_admin$' "$TMPDIR/database-normalized.env" || fail "DATABASE_USER missing from backup"
grep -q '^DATABASE_PASSWORD=s3cr3t$' "$TMPDIR/database-normalized.env" || fail "DATABASE_PASSWORD missing from backup"
echo "PASS: Vault backup produced env file"

cat >"$TMPDIR/restored.env" <<'EOF'
DATABASE_HOST=restored.example.local
DATABASE_PORT=6432
DATABASE_USER=restored_admin
DATABASE_PASSWORD=restored-password
EOF

"$TMPDIR/vault-backup" \
  --url "$BASE_URL/api" \
  --user "$USERNAME" \
  --pass "$PASSWORD" \
  --secret_name kv \
  --secret_path app/restored \
  --restore \
  --input_path "$TMPDIR/restored.env"

RESTORE_BODY=$(curl --silent --show-error --fail \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/kv/data/app/restored")
printf '%s' "$RESTORE_BODY" | grep -q 'restored.example.local' || fail "restore host missing"
printf '%s' "$RESTORE_BODY" | grep -q 'restored_admin' || fail "restore user missing"
printf '%s' "$RESTORE_BODY" | grep -q 'restored-password' || fail "restore password missing"
echo "PASS: env restore wrote secret to Vault"

stat -c '%a' "$TMPDIR/database.env" >/dev/null
stat -c '%a' "$TMPDIR/restored.env" >/dev/null

echo "All vault-backup integration tests passed."

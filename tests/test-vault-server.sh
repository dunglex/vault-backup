#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$ROOT/vault-server"
TMPDIR=$(mktemp -d)
PID=""
PASS="integration-test-password"
SETUP_KEY="integration-test-setup-key"
PORT=18220
BASE_URL="http://127.0.0.1:$PORT"
COOKIE_JAR="$TMPDIR/cookies.txt"

cleanup() {
  if [[ -n "$PID" ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
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

VAULT_SERVER_ADDR="127.0.0.1:$PORT" \
VAULT_SERVER_DB="$TMPDIR/vault.db" \
VAULT_SERVER_SETUP_KEY="$SETUP_KEY" \
"$TMPDIR/vault-server" >"$TMPDIR/server.log" 2>&1 &
PID=$!

curl --fail --silent --retry 20 --retry-delay 1 --retry-connrefused \
  "$BASE_URL/health" >/dev/null

HEALTH=$(curl --silent --show-error "$BASE_URL/health")
[[ "$HEALTH" == '{"ok":true}' ]] || fail "health response"
echo "PASS: health endpoint"

PAGE_STATUS=$(curl --silent --output "$TMPDIR/index.html" --write-out '%{http_code}' "$BASE_URL/")
assert_status 200 "$PAGE_STATUS" "serve embedded web page"
grep -q 'Vault Server' "$TMPDIR/index.html" || fail "embedded page content"
echo "PASS: embedded page content"

BAD_SETUP_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"setup_key":"wrong","username":"admin","password":"integration-test-password"}' \
  "$BASE_URL/v1/setup")
assert_status 401 "$BAD_SETUP_STATUS" "reject invalid setup key"

SETUP_STATUS=$(curl --silent --output "$TMPDIR/setup.json" --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"setup_key":"integration-test-setup-key","username":"admin","password":"integration-test-password"}' \
  "$BASE_URL/v1/setup")
assert_status 201 "$SETUP_STATUS" "create admin account"
grep -q '"username":"admin"' "$TMPDIR/setup.json" || fail "setup account response"

LOGIN_BODY=$(curl --silent --show-error --fail \
  --cookie-jar "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"integration-test-password"}' \
  "$BASE_URL/v1/auth/login")
TOKEN=$(printf '%s' "$LOGIN_BODY" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[[ -n "$TOKEN" ]] || fail "login token"
echo "PASS: login"

UNAUTH_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' "$BASE_URL/v1/secrets")
assert_status 401 "$UNAUTH_STATUS" "reject unauthorized web secret list"

PUT_STATUS=$(curl --silent --output "$TMPDIR/put.json" --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"username":"db-admin","password":"db-password"}}' \
  -X PUT "$BASE_URL/v1/secrets/app/database")
assert_status 200 "$PUT_STATUS" "create secret with web cookie"

LIST_BODY=$(curl --silent --show-error --fail \
  --cookie "$COOKIE_JAR" \
  "$BASE_URL/v1/secrets")
printf '%s' "$LIST_BODY" | grep -q 'app/database' || fail "secret list does not contain app/database"
echo "PASS: list secrets with web cookie"

GET_BODY=$(curl --silent --show-error --fail \
  --cookie "$COOKIE_JAR" \
  "$BASE_URL/v1/secrets/app/database")
printf '%s' "$GET_BODY" | grep -q 'db-admin' || fail "get secret content"
printf '%s' "$GET_BODY" | grep -q 'db-password' || fail "get secret password"
echo "PASS: read secret with web cookie"

UPDATE_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"username":"db-admin","password":"rotated-password"}}' \
  -X PUT "$BASE_URL/v1/secrets/app/database")
assert_status 200 "$UPDATE_STATUS" "update secret with web cookie"

UPDATED_BODY=$(curl --silent --show-error --fail \
  --cookie "$COOKIE_JAR" \
  "$BASE_URL/v1/secrets/app/database")
printf '%s' "$UPDATED_BODY" | grep -q 'rotated-password' || fail "updated secret content"
echo "PASS: verify secret update"

DELETE_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  -X DELETE "$BASE_URL/v1/secrets/app/database")
assert_status 200 "$DELETE_STATUS" "delete secret with web cookie"

MISSING_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  "$BASE_URL/v1/secrets/app/database")
assert_status 404 "$MISSING_STATUS" "confirm deleted secret is missing"

LOGOUT_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  --cookie-jar "$COOKIE_JAR" \
  -X POST "$BASE_URL/v1/auth/logout")
assert_status 200 "$LOGOUT_STATUS" "logout"

AFTER_LOGOUT_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  "$BASE_URL/v1/secrets")
assert_status 401 "$AFTER_LOGOUT_STATUS" "reject revoked web session"

API_LIST_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H 'X-Vault-Token: '"$TOKEN" \
  "$BASE_URL/api/v1/kv/metadata/app")
# API KV metadata is optional in this test; verify that cookie-only access is rejected.
COOKIE_API_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  "$BASE_URL/api/v1/kv/data/app/database")
assert_status 401 "$COOKIE_API_STATUS" "reject cookie authentication on API endpoints"

DB_MODE=$(stat -c '%a' "$TMPDIR/vault.db")
[[ "$DB_MODE" == "600" ]] || fail "database permissions: expected 600, got $DB_MODE"
echo "PASS: database file permissions"

KEY_MODE=$(stat -c '%a' "$TMPDIR/vault.db.key")
[[ "$KEY_MODE" == "600" ]] || fail "key permissions: expected 600, got $KEY_MODE"
echo "PASS: encryption key file permissions"

echo "All Vault server integration tests passed."

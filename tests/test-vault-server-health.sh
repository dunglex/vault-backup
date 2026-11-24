#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/test-common.sh"

PORT=18220
HTTP_PORT=18221
BASE_URL="https://127.0.0.1:$PORT"
HTTP_URL="http://127.0.0.1:$HTTP_PORT"
COOKIE_JAR="$TMPDIR/cookies.txt"

build_vault_server
create_test_certificate
start_vault_server "$PORT" "$HTTP_PORT" "integration-test-setup-key"
wait_for_server "$BASE_URL" "$HTTP_URL"

HEALTH=$(curl --insecure --silent --show-error "$BASE_URL/health")
[[ "$HEALTH" == '{"ok":true}' ]] || fail "health response"
echo "PASS: health endpoint"

API_HEALTH=$(curl --insecure --silent --show-error "$BASE_URL/api/health")
[[ "$API_HEALTH" == '{"ok":true}' ]] || fail "API health response"
echo "PASS: API health endpoint"

HTTP_HEALTH=$(curl --fail --silent --show-error "$HTTP_URL/health")
[[ "$HTTP_HEALTH" == '{"ok":true}' ]] || fail "HTTP health response"
echo "PASS: HTTP health endpoint"

PAGE_STATUS=$(curl --insecure --silent --output "$TMPDIR/index.html" --write-out '%{http_code}' "$BASE_URL/")
assert_status 200 "$PAGE_STATUS" "serve embedded web page"
grep -q 'Vault Server' "$TMPDIR/index.html" || fail "embedded page content"
echo "PASS: embedded page content"

kill -TERM "$SERVER_PID"
wait "$SERVER_PID"
SERVER_PID=""

if curl --insecure --silent --max-time 1 "$BASE_URL/health" >/dev/null; then
  fail "HTTPS listener remained available after shutdown"
fi
if curl --silent --max-time 1 "$HTTP_URL/health" >/dev/null; then
  fail "HTTP listener remained available after shutdown"
fi
grep -q 'Vault server shut down' "$TMPDIR/server.log" || fail "graceful shutdown completion was not logged"

VAULT_SERVER_DB_PASSWORD="integration-test-password" \
  "$TMPDIR/vault-server" --addr "127.0.0.1:0" --db "$TMPDIR/vault.db" \
  --tls-cert "$CERT_FILE" --tls-key "$KEY_FILE" >"$TMPDIR/reopen.log" 2>&1 &
REOPEN_PID=$!
for _ in $(seq 1 50); do
  grep -q 'Vault server shut down' "$TMPDIR/reopen.log" && fail "reopened server unexpectedly stopped"
  grep -q 'Vault server serving HTTPS' "$TMPDIR/reopen.log" && break
  sleep 0.2
done
kill "$REOPEN_PID" 2>/dev/null || fail "server failed to reopen database after shutdown"
wait "$REOPEN_PID"
echo "PASS: graceful shutdown closes listeners and database"

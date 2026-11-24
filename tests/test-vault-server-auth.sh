#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/test-common.sh"

PORT=18222
HTTP_PORT=18223
BASE_URL="https://127.0.0.1:$PORT"
HTTP_URL="http://127.0.0.1:$HTTP_PORT"
COOKIE_JAR="$TMPDIR/cookies.txt"
SETUP_KEY="integration-test-setup-key"

build_vault_server
create_test_certificate
start_vault_server "$PORT" "$HTTP_PORT" "$SETUP_KEY"
wait_for_server "$BASE_URL" "$HTTP_URL"

BAD_SETUP_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"setup_key":"wrong","username":"admin","password":"integration-test-password"}' \
  "$BASE_URL/v1/setup")
assert_status 401 "$BAD_SETUP_STATUS" "reject invalid setup key"

SETUP_STATUS=$(curl --insecure --silent --output "$TMPDIR/setup.json" --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"setup_key":"integration-test-setup-key","username":"admin","password":"integration-test-password"}' \
  "$HTTP_URL/v1/setup")
assert_status 201 "$SETUP_STATUS" "create admin account"
grep -q '"username":"admin"' "$TMPDIR/setup.json" || fail "setup account response"

LOGIN_BODY=$(curl --insecure --silent --show-error --fail \
  --cookie-jar "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"integration-test-password"}' \
  "$BASE_URL/v1/auth/login")
TOKEN=$(printf '%s' "$LOGIN_BODY" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[[ -n "$TOKEN" ]] || fail "login token"
echo "PASS: login"

UNAUTH_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' "$BASE_URL/v1/secrets")
assert_status 401 "$UNAUTH_STATUS" "reject unauthorized web secret list"

LOGOUT_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  --cookie-jar "$COOKIE_JAR" \
  -X POST "$BASE_URL/v1/auth/logout")
assert_status 200 "$LOGOUT_STATUS" "logout"

AFTER_LOGOUT_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  "$BASE_URL/v1/secrets")
assert_status 401 "$AFTER_LOGOUT_STATUS" "reject revoked web session"

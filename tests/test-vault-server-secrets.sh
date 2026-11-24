#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/test-common.sh"

PORT=18224
HTTP_PORT=18225
BASE_URL="https://127.0.0.1:$PORT"
HTTP_URL="http://127.0.0.1:$HTTP_PORT"
COOKIE_JAR="$TMPDIR/cookies.txt"
SETUP_KEY="integration-test-setup-key"

build_vault_server
create_test_certificate
start_vault_server "$PORT" "$HTTP_PORT" "$SETUP_KEY"
wait_for_server "$BASE_URL" "$HTTP_URL"

curl --insecure --silent --show-error --fail \
  -H 'Content-Type: application/json' \
  -d '{"setup_key":"integration-test-setup-key","username":"admin","password":"integration-test-password"}' \
  "$HTTP_URL/v1/setup" >/dev/null
curl --insecure --silent --show-error --fail \
  --cookie-jar "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"integration-test-password"}' \
  "$BASE_URL/v1/auth/login" >/dev/null

PUT_STATUS=$(curl --insecure --silent --output "$TMPDIR/put.json" --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"username":"db-admin","password":"db-password"}}' \
  -X PUT "$BASE_URL/v1/secrets/app/database")
assert_status 200 "$PUT_STATUS" "create secret with web cookie"

LIST_BODY=$(curl --insecure --silent --show-error --fail --cookie "$COOKIE_JAR" "$BASE_URL/v1/secrets")
printf '%s' "$LIST_BODY" | grep -q 'app/database' || fail "secret list does not contain app/database"
echo "PASS: list secrets with web cookie"

GET_BODY=$(curl --insecure --silent --show-error --fail --cookie "$COOKIE_JAR" "$BASE_URL/v1/secrets/app/database")
printf '%s' "$GET_BODY" | grep -q 'db-admin' || fail "get secret content"
printf '%s' "$GET_BODY" | grep -q 'db-password' || fail "get secret password"
echo "PASS: read secret with web cookie"

UPDATE_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" -H 'Content-Type: application/json' \
  -d '{"data":{"username":"db-admin","password":"rotated-password"}}' \
  -X PUT "$BASE_URL/v1/secrets/app/database")
assert_status 200 "$UPDATE_STATUS" "update secret with web cookie"

UPDATED_BODY=$(curl --insecure --silent --show-error --fail --cookie "$COOKIE_JAR" "$BASE_URL/v1/secrets/app/database")
printf '%s' "$UPDATED_BODY" | grep -q 'rotated-password' || fail "updated secret content"
echo "PASS: verify secret update"

DELETE_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" -X DELETE "$BASE_URL/v1/secrets/app/database")
assert_status 200 "$DELETE_STATUS" "delete secret with web cookie"

MISSING_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" "$BASE_URL/v1/secrets/app/database")
assert_status 404 "$MISSING_STATUS" "confirm deleted secret is missing"

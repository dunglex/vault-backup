#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/test-common.sh"

PORT=18226
HTTP_PORT=18227
BASE_URL="https://127.0.0.1:$PORT"
HTTP_URL="http://127.0.0.1:$HTTP_PORT"
COOKIE_JAR="$TMPDIR/cookies.txt"

build_vault_server
create_test_certificate
start_vault_server "$PORT" "$HTTP_PORT" "integration-test-setup-key"
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

COOKIE_API_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  "$BASE_URL/api/v1/kv/data/app/database")
assert_status 401 "$COOKIE_API_STATUS" "reject cookie authentication on API endpoints"

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

HTTP_HEALTH=$(curl --fail --silent --show-error "$HTTP_URL/health")
[[ "$HTTP_HEALTH" == '{"ok":true}' ]] || fail "HTTP health response"
echo "PASS: HTTP health endpoint"

PAGE_STATUS=$(curl --insecure --silent --output "$TMPDIR/index.html" --write-out '%{http_code}' "$BASE_URL/")
assert_status 200 "$PAGE_STATUS" "serve embedded web page"
grep -q 'Vault Server' "$TMPDIR/index.html" || fail "embedded page content"
echo "PASS: embedded page content"

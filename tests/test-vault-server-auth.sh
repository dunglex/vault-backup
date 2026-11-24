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
  -d '{"setup_key":"wrong","username":"admin","password":"integration-test-password","password_confirmation":"integration-test-password"}' \
  "$BASE_URL/v1/setup")
assert_status 401 "$BAD_SETUP_STATUS" "reject invalid setup key"

MISMATCH_SETUP_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"setup_key":"integration-test-setup-key","username":"admin","password":"integration-test-password","password_confirmation":"different-password"}' \
  "$BASE_URL/v1/setup")
assert_status 400 "$MISMATCH_SETUP_STATUS" "reject mismatched setup passwords"

SETUP_STATUS=$(curl --insecure --silent --output "$TMPDIR/setup.json" --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"setup_key":"integration-test-setup-key","username":"admin","password":"integration-test-password","password_confirmation":"integration-test-password"}' \
  "$HTTP_URL/v1/setup")
assert_status 201 "$SETUP_STATUS" "create admin account"
grep -q '"username":"admin"' "$TMPDIR/setup.json" || fail "setup account response"

SECOND_SETUP_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"setup_key":"integration-test-setup-key","username":"other","password":"integration-test-password","password_confirmation":"integration-test-password"}' \
  "$HTTP_URL/v1/setup")
assert_status 409 "$SECOND_SETUP_STATUS" "disable admin creation after setup"

LOGIN_BODY=$(curl --insecure --silent --show-error --fail \
  --cookie-jar "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"integration-test-password"}' \
  "$BASE_URL/v1/auth/login")
TOKEN=$(printf '%s' "$LOGIN_BODY" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[[ -n "$TOKEN" ]] || fail "login token"
echo "PASS: login"

SESSION_API_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H "X-Vault-Token: $TOKEN" \
  "$BASE_URL/api/v1/kv/data/session/test")
assert_status 401 "$SESSION_API_STATUS" "reject admin login token on API endpoints"

LDAP_LOGIN_BODY=$(curl --insecure --silent --show-error --fail \
  -H 'Content-Type: application/json' \
  -d '{"password":"integration-test-password"}' \
  -X PUT "$BASE_URL/api/v1/auth/ldap/login/admin")
LDAP_TOKEN=$(printf '%s' "$LDAP_LOGIN_BODY" | sed -n 's/.*"client_token":"\([^"]*\)".*/\1/p')
[[ -n "$LDAP_TOKEN" ]] || fail "LDAP-compatible login token"

LDAP_API_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H "Authorization: Bearer $LDAP_TOKEN" \
  "$BASE_URL/api/v1/kv/data/session/test")
assert_status 401 "$LDAP_API_STATUS" "reject LDAP login token on API endpoints"

FAILED_LOGIN_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"wrong-password"}' \
  "$BASE_URL/v1/auth/login")
assert_status 401 "$FAILED_LOGIN_STATUS" "failed login for audit"

LOGIN_AUDIT=$(curl --insecure --silent --show-error --fail --cookie "$COOKIE_JAR" \
  "$BASE_URL/v1/audit?action=login")
printf '%s' "$LOGIN_AUDIT" | grep -q '"outcome":"success"' || fail "successful login audit missing"
printf '%s' "$LOGIN_AUDIT" | grep -q '"outcome":"failure"' || fail "failed login audit missing"
echo "PASS: audit successful and failed logins"

UNAUTH_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' "$BASE_URL/v1/secrets")
assert_status 401 "$UNAUTH_STATUS" "reject unauthorized web secret list"

TOKEN_RESPONSE=$(curl --insecure --silent --show-error --fail \
  --cookie "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d '{"name":"backup-agent","expires_in":"1 day"}' \
  "$BASE_URL/v1/tokens")
API_TOKEN=$(printf '%s' "$TOKEN_RESPONSE" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
API_TOKEN_ID=$(printf '%s' "$TOKEN_RESPONSE" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
[[ -n "$API_TOKEN" && -n "$API_TOKEN_ID" ]] || fail "create API token"
CREATED_AT=$(printf '%s' "$TOKEN_RESPONSE" | sed -n 's/.*"created_at":"\([^"]*\)".*/\1/p')
EXPIRES_AT=$(printf '%s' "$TOKEN_RESPONSE" | sed -n 's/.*"expires_at":"\([^"]*\)".*/\1/p')
TOKEN_LIFETIME=$(( $(date -d "$EXPIRES_AT" +%s) - $(date -d "$CREATED_AT" +%s) ))
[[ "$TOKEN_LIFETIME" -eq 2592000 ]] || fail "API token lifetime is not fixed at 30 days"
echo "PASS: create fixed-expiry API token"

TOKEN_PUT_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H "X-Vault-Token: $API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"managed":"token"}}' \
  -X PUT "$BASE_URL/api/v1/kv/data/token/test")
assert_status 200 "$TOKEN_PUT_STATUS" "authenticate with managed API token"

TOKEN_GET_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H "X-Vault-Token: $API_TOKEN" \
  "$BASE_URL/api/v1/kv/data/token/test")
assert_status 200 "$TOKEN_GET_STATUS" "read secret with managed API token"

TOKEN_BAD_REQUEST_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H "X-Vault-Token: $API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"invalid":true}' \
  -X PUT "$BASE_URL/api/v1/kv/data/token/test")
assert_status 400 "$TOKEN_BAD_REQUEST_STATUS" "reject invalid managed API request"

INVALID_PATH_STATUS=$(curl --insecure --silent --output "$TMPDIR/invalid-path.json" --write-out '%{http_code}' \
  -H "X-Vault-Token: $API_TOKEN" \
  "$BASE_URL/api/v1/kv/data/invalid_path")
assert_status 400 "$INVALID_PATH_STATUS" "reject invalid API secret path"
grep -q 'each segment must be 1-127 characters' "$TMPDIR/invalid-path.json" || fail "invalid API path error message"

INVALID_LIST_PATH_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H "X-Vault-Token: $API_TOKEN" \
  -X LIST "$BASE_URL/api/v1/kv/metadata/invalid.path")
assert_status 400 "$INVALID_LIST_PATH_STATUS" "reject invalid API metadata path"

API_AUDIT=$(curl --insecure --silent --show-error --fail --cookie "$COOKIE_JAR" \
  "$BASE_URL/v1/audit?source=api&q=token%2Ftest")
printf '%s' "$API_AUDIT" | grep -q '"action":"create"' || fail "API create audit missing"
printf '%s' "$API_AUDIT" | grep -q '"action":"read"' || fail "API read audit missing"
printf '%s' "$API_AUDIT" | grep -q '"outcome":"failure"' || fail "API failed request audit missing"
printf '%s' "$API_AUDIT" | grep -q '"source":"api"' || fail "API audit source missing"
echo "PASS: audit successful and failed managed API operations"

TOKEN_LIST=$(curl --insecure --silent --show-error --fail --cookie "$COOKIE_JAR" "$BASE_URL/v1/tokens")
printf '%s' "$TOKEN_LIST" | grep -q '"name":"backup-agent"' || fail "list API token"
echo "PASS: list managed API tokens"

REVOKE_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  -X DELETE "$BASE_URL/v1/tokens/$API_TOKEN_ID")
assert_status 200 "$REVOKE_STATUS" "revoke API token"

REVOKED_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H "X-Vault-Token: $API_TOKEN" \
  "$BASE_URL/api/v1/kv/data/token/test")
assert_status 401 "$REVOKED_STATUS" "reject revoked API token"

LOGOUT_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  --cookie-jar "$COOKIE_JAR" \
  -X POST "$BASE_URL/v1/auth/logout")
assert_status 200 "$LOGOUT_STATUS" "logout"

AFTER_LOGOUT_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "$COOKIE_JAR" \
  "$BASE_URL/v1/secrets")
assert_status 401 "$AFTER_LOGOUT_STATUS" "reject revoked web session"

BAD_LOGIN_1=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"wrong-password"}' \
  "$BASE_URL/v1/auth/login")
BAD_LOGIN_2=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"password":"wrong-password"}' \
  -X PUT "$BASE_URL/api/v1/auth/ldap/login/admin")
BAD_LOGIN_3=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"wrong-password"}' \
  "$HTTP_URL/v1/auth/login")
BAD_LOGIN_4=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"password":"wrong-password"}' \
  -X PUT "$BASE_URL/api/v1/auth/ldap/login/admin")
assert_status 401 "$BAD_LOGIN_1" "count first failed web login"
assert_status 401 "$BAD_LOGIN_2" "share limit with failed LDAP login"
assert_status 429 "$BAD_LOGIN_3" "normalize client ports and listeners"
assert_status 429 "$BAD_LOGIN_4" "throttle shared login endpoints"

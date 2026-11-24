#!/usr/bin/env bash

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TMPDIR=$(mktemp -d)
SERVER_PID=""
CERT_FILE="$TMPDIR/test-cert.pem"
KEY_FILE="$TMPDIR/test-key.pem"
USERNAME="admin"
PASSWORD="backup-test-password"
SETUP_KEY="backup-test-setup-key"
PORT=18210
HTTP_PORT=18211
BASE_URL="http://127.0.0.1:$HTTP_PORT"

cleanup_backup_test() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup_backup_test EXIT

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

build_backup_binaries() {
  cd "$ROOT"
  go build -o "$TMPDIR/vault-server" ./cmd/vault-server
  go build -o "$TMPDIR/vault-backup" ./cmd/vault-backup
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=127.0.0.1' \
    -keyout "$KEY_FILE" -out "$CERT_FILE" >/dev/null 2>&1
}

start_backup_server() {
  VAULT_SERVER_ADDR="127.0.0.1:$PORT" \
  VAULT_SERVER_HTTP_ADDR="127.0.0.1:$HTTP_PORT" \
  VAULT_SERVER_DB="$TMPDIR/vault.db" \
  VAULT_SERVER_DB_PASSWORD="integration-test-password" \
  VAULT_SERVER_SETUP_KEY="$SETUP_KEY" \
  "$TMPDIR/vault-server" --tls-cert "$CERT_FILE" --tls-key "$KEY_FILE" >"$TMPDIR/server.log" 2>&1 &
  SERVER_PID=$!

  curl --insecure --fail --silent --retry 20 --retry-delay 1 --retry-connrefused \
    "$BASE_URL/health" >/dev/null
}

setup_backup_account() {
  SETUP_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
    -H 'Content-Type: application/json' \
    -d '{"setup_key":"backup-test-setup-key","username":"admin","password":"backup-test-password"}' \
    "$BASE_URL/v1/setup")
  assert_status 201 "$SETUP_STATUS" "set up vault server"
}

login_backup_account() {
  LOGIN_BODY=$(curl --insecure --silent --show-error --fail \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"backup-test-password"}' \
    "$BASE_URL/v1/auth/login")
  TOKEN=$(printf '%s' "$LOGIN_BODY" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  [[ -n "$TOKEN" ]] || fail "obtain API token"
}

create_backup_api_token() {
  COOKIE_JAR="$TMPDIR/cookies.txt"
  curl --insecure --silent --show-error --fail \
    --cookie-jar "$COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"backup-test-password"}' \
    "$BASE_URL/v1/auth/login" >/dev/null
  MANAGED_TOKEN_BODY=$(curl --insecure --silent --show-error --fail \
    --cookie "$COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    -d '{"name":"backup-test"}' \
    "$BASE_URL/v1/tokens")
  MANAGED_TOKEN=$(printf '%s' "$MANAGED_TOKEN_BODY" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  [[ -n "$MANAGED_TOKEN" ]] || fail "create managed API token"
}

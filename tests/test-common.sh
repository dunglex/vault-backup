#!/usr/bin/env bash

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TMPDIR=$(mktemp -d)
SERVER_PID=""
CERT_FILE="$TMPDIR/test-cert.pem"
KEY_FILE="$TMPDIR/test-key.pem"

cleanup_test() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}

trap cleanup_test EXIT

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

build_vault_server() {
  cd "$ROOT"
  go build -o "$TMPDIR/vault-server" ./cmd/vault-server
}

create_test_certificate() {
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=127.0.0.1' \
    -keyout "$KEY_FILE" -out "$CERT_FILE" >/dev/null 2>&1
}

start_vault_server() {
  local port=$1
  local http_port=$2
  local setup_key=$3

  VAULT_SERVER_ADDR="127.0.0.1:$port" \
  VAULT_SERVER_HTTP_ADDR="127.0.0.1:$http_port" \
  VAULT_SERVER_DB="$TMPDIR/vault.db" \
  VAULT_SERVER_DB_PASSWORD="integration-test-password" \
  VAULT_SERVER_SETUP_KEY="$setup_key" \
  "$TMPDIR/vault-server" --tls-cert "$CERT_FILE" --tls-key "$KEY_FILE" >"$TMPDIR/server.log" 2>&1 &
  SERVER_PID=$!
}

wait_for_server() {
  local https_url=$1
  local http_url=$2
  curl --insecure --fail --silent --retry 20 --retry-delay 1 --retry-connrefused \
    "$https_url/health" >/dev/null
  curl --fail --silent --retry 20 --retry-delay 1 --retry-connrefused \
    "$http_url/health" >/dev/null
}

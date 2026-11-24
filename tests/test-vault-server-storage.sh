#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/test-common.sh"

PORT=18228
HTTP_PORT=18229
BASE_URL="https://127.0.0.1:$PORT"
HTTP_URL="http://127.0.0.1:$HTTP_PORT"

build_vault_server
create_test_certificate
start_vault_server "$PORT" "$HTTP_PORT" "integration-test-setup-key"
wait_for_server "$BASE_URL" "$HTTP_URL"

DB_MODE=$(stat -c '%a' "$TMPDIR/vault.db")
[[ "$DB_MODE" == "600" ]] || fail "database permissions: expected 600, got $DB_MODE"
echo "PASS: database file permissions"

DB_HEADER=$(od -An -tx1 -N15 "$TMPDIR/vault.db" | tr -d ' \n')
[[ "$DB_HEADER" != "53514c69746520666f726d6174203300" ]] || fail "new database is plaintext SQLite"
echo "PASS: database file is encrypted"

KEY_MODE=$(stat -c '%a' "$TMPDIR/vault.db.key")
[[ "$KEY_MODE" == "600" ]] || fail "key permissions: expected 600, got $KEY_MODE"
echo "PASS: encryption key file permissions"

AUDIT_MODE=$(stat -c '%a' "$TMPDIR/audit.db")
[[ "$AUDIT_MODE" == "600" ]] || fail "audit database permissions: expected 600, got $AUDIT_MODE"
AUDIT_HEADER=$(od -An -tx1 -N16 "$TMPDIR/audit.db" | tr -d ' \n')
[[ "$AUDIT_HEADER" == "53514c69746520666f726d6174203300" ]] || fail "audit database should be plaintext SQLite"
echo "PASS: separate plaintext audit database"

"$ROOT/scripts/backup-vault-server.sh" \
  --db "$TMPDIR/vault.db" \
  --env-file "" \
  --output "$TMPDIR/vault-server.tar.gz" >/dev/null
tar -tzf "$TMPDIR/vault-server.tar.gz" >"$TMPDIR/archive-files.txt"
grep -q 'vault-server/database/audit.db$' "$TMPDIR/archive-files.txt" || fail "server backup omitted audit database"
echo "PASS: server backup includes audit database"

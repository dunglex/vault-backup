#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/test-vault-backup-common.sh"

build_backup_binaries
start_backup_server
setup_backup_account
login_backup_account
create_backup_api_token

PUT_STATUS=$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H "Authorization: Bearer $MANAGED_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"DATABASE_HOST":"db.example.local","DATABASE_PORT":"5432","DATABASE_USER":"backup_admin","DATABASE_PASSWORD":"s3cr3t"}}' \
  -X PUT "$BASE_URL/api/v1/kv/data/app/database")
assert_status 200 "$PUT_STATUS" "seed KV v2 source secret"

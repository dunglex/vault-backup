#!/usr/bin/env bash
set -euo pipefail

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

"$TEST_DIR/test-vault-backup-setup.sh"
"$TEST_DIR/test-vault-backup-seed.sh"
"$TEST_DIR/test-vault-backup-env.sh"
"$TEST_DIR/test-vault-backup-restore.sh"

echo "All vault-backup integration tests passed."

#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

cd "$ROOT_DIR"
mkdir -p bin
go build --ldflags="-s -w" -o bin/mkcert ./cmd/mkcert
go build --ldflags="-s -w" -o bin/vault-backup ./cmd/vault-backup
CGO_ENABLED=1 go build --ldflags="-s -w" -o bin/vault-server ./cmd/vault-server

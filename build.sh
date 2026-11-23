#!/usr/bin/env bash

set -e

go build -o bin/vault-backup ./cmd/vault-backup
go build -o bin/vault-server ./cmd/vault-server
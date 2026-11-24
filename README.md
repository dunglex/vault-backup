# Vault Backup and Vault Server

This repository contains two Go applications:

- [`vault-backup`](cmd/vault-backup/README.md): exports Vault KV secrets to files and restores files into Vault.
- [`vault-server`](cmd/vault-server/README.md): a SQLite-backed Vault-compatible server with HTTPS by default and an explicitly opt-in HTTP listener.

## Requirements

- Go 1.26 or later
- A C compiler to build the SQLCipher-backed server

Build both applications with:

```bash
./scripts/build.sh
```

See each application's guide for configuration, deployment, and tests:

- [`vault-backup` guide](cmd/vault-backup/README.md)
- [`vault-server` guide](cmd/vault-server/README.md)

## Testings

- Python 3.10 or later

Automation tests:

 - Test actual data backup/restore [`test_data`](test_data/README.md)
 - Test using a test server [`tests`](test/README.md)
 
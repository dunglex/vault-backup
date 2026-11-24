# Tests

The integration test suite is organized into three major parts:

1. **Vault server tests** - `test_vault_server.py`
2. **Vault backup tests** - `test_vault_backup.py`
3. **Dummy secret generation** - `generate_dummy_secrets.py`

Shared HTTP client, server lifecycle, and assertion helpers live in
`test_common.py`.

## Vault server tests

Run the complete Vault server integration suite from the repository root:

```bash
python3 ./tests/test_vault_server.py
```

The runner builds the server, starts isolated HTTP and HTTPS listeners with
temporary certificates and databases, executes the server test modules, and
cleans up afterward.

The suite covers health checks, authentication, secrets, API behavior, and
storage:

- `test_vault_server_health.py`
- `test_vault_server_auth.py`
- `test_vault_server_secrets.py`
- `test_vault_server_api.py`
- `test_vault_server_storage.py`

## Vault backup tests

Run the complete Vault backup integration suite from the repository root:

```bash
python3 ./tests/test_vault_backup.py
```

The runner builds the backup and server binaries, starts an isolated server,
and executes setup, seeding, environment, and restore scenarios:

- `test_vault_backup_setup.py`
- `test_vault_backup_seed.py`
- `test_vault_backup_env.py`
- `test_vault_backup_restore.py`

## Generate dummy secrets

Use `generate_dummy_secrets.py` to populate a running Vault-compatible server
with deterministic load-test secrets:

```bash
python3 ./tests/generate_dummy_secrets.py \
  --url https://127.0.0.1:8200/api \
  --token "$VAULT_API_TOKEN" \
  --count 1000 \
  --prefix dummy/load-test \
  --insecure-tls
```

The script creates and verifies secrets in `kv/dummy/load-test` by default and
supports `--cleanup` to delete them after verification. It can also be
configured with `VAULT_URL`, `VAULT_TOKEN`, and `VAULT_SECRET_NAME`.
# Tests

The integration test suite is organized into 2 major parts:

1. **Vault server tests** - `test_vault_server.py`
2. **Vault backup tests** - `test_vault_backup.py`

Shared HTTP client, server lifecycle, and assertion helpers live in
`test_common.py`.

## Vault server tests

Run the complete Vault server integration suite from the repository root:

```bash
python3 ./test_vault_server.py
```

The runner builds the server, starts isolated HTTP and HTTPS listeners with
temporary certificates and databases, executes the server test modules, and
cleans up afterward.

The suite covers health checks, authentication, secrets, API behavior, and
storage, including a database backup/restore round trip:

- `test_vault_server_health.py`
- `test_vault_server_auth.py`
- `test_vault_server_secrets.py`
- `test_vault_server_api.py`
- `test_vault_server_storage.py`

## Vault backup tests

Run the complete Vault backup integration suite from the repository root:

```bash
python3 ./test_vault_backup.py
```

The runner builds the backup and server binaries, starts an isolated server,
and executes setup, seeding, environment, and restore scenarios:

- `test_vault_backup_setup.py`
- `test_vault_backup_seed.py`
- `test_vault_backup_env.py`
- `test_vault_backup_restore.py`

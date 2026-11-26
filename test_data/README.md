## Generate dummy secrets

Generate local JSON files under `test_data/`. File paths become Vault secret
paths (without the `.json` extension), and each JSON file contains that
secret's value:

```bash
python3 ./generate_dummy_secrets.py \
  --count 1000 \
  --prefix apps/production \
  --prefix databases/postgres \
  --prefix teams/platform
```

Without `--prefix`, the generator writes 100 files under each of its built-in
prefixes. Restore JSON files through `vault-backup` by setting the API URL and
managed token:

```bash
VAULT_URL=https://127.0.0.1:8200/api \
VAULT_TOKEN="$VAULT_API_TOKEN" \
python3 ./test_data/restore_dummy_secrets_with_vault_backup.py --insecure-tls
```

Use `--input-dir`, `--mount`, or `--binary` to override their defaults. The
script restores each JSON file with `bin/vault-backup --restore`, using its
relative path as the Vault secret path. The mount only selects the API route;
it is not prepended to the secret path, and all mounts share the same secret
namespace. Use `--ca-cert` instead of
`--insecure-tls` when the server certificate is issued by a trusted CA. Paths
passed to `--ca-cert`, `--client-cert`, and `--client-key` are resolved relative
to the directory from which the script is run.

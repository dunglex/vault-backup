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
managed token. First build the current backup client:

```bash
go build -o bin/vault-backup ./cmd/vault-backup
```

Then run the restore:

```bash
VAULT_URL=https://127.0.0.1:8200/api \
VAULT_TOKEN="$VAULT_API_TOKEN" \
python3 ./test_data/restore_dummy_secrets_with_vault_backup.py --insecure-tls
```

Use `--input-dir`, `--mount`, or `--binary` to override their defaults. The
script restores each JSON file with `bin/vault-backup --restore`, using its
relative path as the secret path within the selected mount. The default mount
is `kv`; create any other mount in `/mounts.html` and grant it to the API token
before restoring to it. Mounts are separate secret namespaces. Use `--ca-cert` instead of
`--insecure-tls` when the server certificate is issued by a trusted CA. Paths
passed to `--ca-cert`, `--client-cert`, and `--client-key` are resolved relative
to the directory from which the script is run. A server-origin URL with no
path automatically uses `/api`; specify the full API URL when using a reverse
proxy path. Rebuild `bin/vault-backup` after updating the source, especially
if it requests LDAP credentials instead of accepting a managed API token.

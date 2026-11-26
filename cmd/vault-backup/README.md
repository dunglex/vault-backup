# vault-backup

`vault-backup` exports Vault KV secrets to local files and restores files into Vault.

## Build

From the repository root:

```bash
go build -o bin/vault-backup ./cmd/vault-backup
```

## Configuration

Supply options as flags or as environment variables with the `VAULT_` prefix.
Invalid or incomplete configuration is rejected with exit status 2 before connecting to Vault.

| Flag | Environment variable | Description |
| --- | --- | --- |
| `--url` | `VAULT_URL` | Vault API URL, including `/api` when using `vault-server` |
| `--user` | `VAULT_USER` | Vault username |
| `--pass` | `VAULT_PASS` | Vault password |
| `--token` | `VAULT_TOKEN` | Managed API token (alternative to username/password; cannot be combined with user/pass) |
| `--secret_name` | `VAULT_SECRET_NAME` | API mount/name |
| `--secret_path` | `VAULT_SECRET_PATH` | Secret path for backup, without the mount |
| `--output_mode` | `VAULT_OUTPUT_MODE` | `all`, `data`, or `file` (default: `all`) |
| `--output_format` | `VAULT_OUTPUT_FORMAT` | `json`, `yaml`, `ini`, or `env` (default: `json`) |
| `--output_path` | `VAULT_OUTPUT_PATH` | Output file or directory (default: `.`) |
| `--insecure` | `VAULT_INSECURE` | Skip TLS certificate verification |
| `--restore` | `VAULT_RESTORE` | Restore mode |
| `--input_path` | `VAULT_INPUT_PATH` | Input file or directory for restore mode |
| `--ca_cert` | `VAULT_CA_CERT` | CA certificate PEM that verifies the Vault server |
| `--client_cert` | `VAULT_CLIENT_CERT` | Client certificate PEM for mutual TLS |
| `--client_key` | `VAULT_CLIENT_KEY` | Client private key PEM for mutual TLS |
| `--tls_server_name` | `VAULT_TLS_SERVER_NAME` | Optional TLS server-name override |

Use HTTPS for direct TLS connections. HTTP is insecure and prints a warning when selected; use it only for private, trusted ingress networks. Do not use `--insecure` with untrusted networks.

Backup files are written with mode `0600`. Output directories created by `vault-backup` use mode `0700`.

Folder backups recurse through nested secret paths. For vault-server, the API
mount is only used for routing and is not included in secret paths; all mounts
share the same path namespace. Backup and restore operations exit with a
non-zero status if any item fails, even when other items were processed
successfully.

When the administrator has created a managed API token, `vault-backup` can use it directly:

```bash
VAULT_TOKEN="$VAULT_API_TOKEN" ./bin/vault-backup \
  --url https://vault.example:8200/api \
  --secret_name kv \
  --secret_path app/database \
  --output_mode file \
  --output_format env \
  --output_path ./database.env
```

For vault-server, create a managed API token in the web panel and pass it with `--token`. Username/password login credentials authorize the web session only; they do not authorize `/api/...`.

For mutual TLS, configure the server CA and the backup client certificate/key:

```bash
./bin/vault-backup \
  --url https://vault.example:8200/api \
  --ca_cert /etc/vault/tls/ca.crt \
  --client_cert /etc/vault/tls/backup.crt \
  --client_key /etc/vault/tls/backup.key \
  --tls_server_name vault.example \
  --token "$VAULT_API_TOKEN" \
  --secret_name kv \
  --secret_path app/database \
  --output_mode file \
  --output_format env \
  --output_path ./database.env
```

Do not combine `--insecure` with custom CA or client-certificate settings.

Managed client certificates expire at the same time as their API token. Token
lifetimes can be selected from 1 to 365 days when creating the token. Replacing
a certificate for an existing token does not extend the token's expiry; create
a replacement token and certificate before expiry.

When server-side mTLS enforcement is enabled, use HTTPS and a current
`vault-backup` version. Older versions do not send the required client
certificate protocol marker and are rejected by the server.

For authorization failures, HTTP 401 means Vault rejected the API token; use
a current managed token from `/tokens.html` and check that it has not expired
or been revoked. HTTP 403 can indicate a missing or mismatched client
certificate when mTLS is enforced.

## Back up a secret

```bash
./bin/vault-backup \
  --url http://vault.example:8201/api \
  --token "$VAULT_API_TOKEN" \
  --secret_name kv \
  --secret_path app/database \
  --output_mode file \
  --output_format env \
  --output_path ./database.env
```

## Restore a secret

```bash
./bin/vault-backup \
  --url http://vault.example:8201/api \
  --token "$VAULT_API_TOKEN" \
  --secret_name kv \
  --restore \
  --input_path ./database.env
```

## Test

From the repository root:

```bash
python3 ./tests/test_vault_backup.py
```

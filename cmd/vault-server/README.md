# vault-server

`vault-server` is a SQLite-backed Vault-compatible server. HTTPS is the default transport. New databases are encrypted with SQLCipher using the protected `vault.db.key` file. Existing plaintext SQLite databases are rejected unless explicitly allowed with the plaintext opt-in; that mode is insecure and is not migrated automatically.

## Requirements

- Go 1.26 or later
- A C compiler for the SQLCipher driver
- OpenSSL for integration tests

## Local HTTPS development

The bundled mkcert helper creates a certificate for `localhost`, `127.0.0.1`, and `::1` if no certificate/key pair exists. Install its local CA once if you want browsers and clients to trust the development certificate:

```bash
./scripts/build.sh
./bin/mkcert -install
./tests/start-vault-server.sh
```

Open `https://localhost:8200/`. The generated files are `tests/data/localhost.pem` and `tests/data/localhost-key.pem`. Keep the local CA private key in its CA root directory protected.

The startup script uses `tests/data/vault.db`, `tests/data/vault.db.key`, and `tests/data/vault.db.setup-key`.

## Configuration from .env

By default, the server loads `.env` from the current working directory. Existing process environment variables take precedence over values in the file:

```dotenv
VAULT_SERVER_DB_PASSWORD=use-a-long-random-password
VAULT_SERVER_ADDR=127.0.0.1:8200
VAULT_SERVER_HTTP_ADDR=
VAULT_SERVER_DB=/var/lib/vault/vault.db
VAULT_SERVER_TLS_CERT=/etc/vault/tls/server.crt
VAULT_SERVER_TLS_KEY=/etc/vault/tls/server.key
```

Start it with:

```bash
./bin/vault-server
```

Use another file with `--env-file` or `VAULT_SERVER_ENV_FILE`:

```bash
./bin/vault-server --env-file /etc/vault/server.env
```

Restrict `.env` permissions to `0600` because it contains the database password.

## Back up server state

Create a sensitive filesystem tarball containing the database, its protected key, setup key, TLS files, and optional `.env`:

```bash
./tests/backup-vault-server.sh \
  --db /var/lib/vault/vault.db \
  --env-file /etc/vault/server.env \
  --tls-cert /etc/vault/tls/server.crt \
  --tls-key /etc/vault/tls/server.key \
  --mtls-ca-cert /etc/vault/tls/client-ca.crt \
  --output /secure/backups/vault-server.tar.gz
```

The archive is created with mode `0600` and includes SHA-256 checksums in `vault-server/manifest.txt`. Stop or quiesce the server before backup for the most consistent database snapshot.

Restore a backup into a clean `/data` directory:

```bash
./scripts/restore-vault-server.sh \
  --data-dir /data \
  /secure/backups/vault-server.tar.gz
```

The restore refuses to overwrite a non-empty destination unless `--replace` is specified. It verifies SHA-256 checksums before installing files with restricted permissions.

## Mutual TLS

Enable mTLS on the HTTPS listener with a PEM-encoded CA bundle containing the certificates that may authenticate Vault clients:

```bash
./bin/vault-server \
  --mtls-ca-cert /etc/vault/tls/client-ca.crt \
  --db /var/lib/vault/vault.db \
  --tls-cert /etc/vault/tls/server.crt \
  --tls-key /etc/vault/tls/server.key
```

The environment variable is `VAULT_SERVER_MTLS_CA_CERT`. When configured, the HTTPS listener requires every client to present a certificate signed by this CA. TLS 1.2 or newer is enforced.

## Database key password

The server requires a password to decrypt the database key file:

```bash
./bin/vault-server \
  --db-password "$VAULT_DB_PASSWORD" \
  --db /secure/location/vault.db \
  --tls-cert /secure/location/server.crt \
  --tls-key /secure/location/server.key
```

The equivalent environment variable is `VAULT_SERVER_DB_PASSWORD`. The environment variable is preferred for automation and avoids exposing the password in process listings:

```bash
export VAULT_SERVER_DB_PASSWORD='use-a-long-random-password'
./bin/vault-server --db /secure/location/vault.db --tls-cert server.crt --tls-key server.key
```

New database keys are 128 random bytes and are stored in `<db>.key` using Argon2id plus AES-GCM. The key file is also restricted to mode `0600`. A wrong password is fatal at startup and the server exits. Legacy raw key files, including 32-byte keys, are not supported or migrated; back up the database, key file, and database password using separate secure channels.

## HTTP and HTTPS startup options

The server starts only HTTPS by default. HTTPS requires a certificate and private key. HTTP is opt-in: set `--http-addr` or `VAULT_SERVER_HTTP_ADDR` explicitly; starting HTTP prints an insecure-awareness warning:

```bash
./bin/vault-server \
  --addr 127.0.0.1:8200 \
  --http-addr 127.0.0.1:8201 \
  --db /secure/location/vault.db \
  --tls-cert /secure/location/localhost.pem \
  --tls-key /secure/location/localhost-key.pem
```

Environment variables are also supported:

```bash
export VAULT_SERVER_ADDR=127.0.0.1:8200
export VAULT_SERVER_HTTP_ADDR=127.0.0.1:8201
export VAULT_SERVER_DB=/secure/location/vault.db
export VAULT_SERVER_TLS_CERT=/secure/location/server.crt
export VAULT_SERVER_TLS_KEY=/secure/location/server.key
export VAULT_SERVER_ALLOW_PLAINTEXT_DB=false
./bin/vault-server
```

Existing plaintext SQLite databases are refused by default. To open one anyway, explicitly acknowledge the insecure mode:

```bash
./bin/vault-server --allow-plaintext-db --db /secure/location/vault.db ...
```

The plaintext opt-in can also be set with `VAULT_SERVER_ALLOW_PLAINTEXT_DB=true`. It does not encrypt or migrate the database.

## Production deployment

Use certificates issued by a trusted certificate authority. Configure the ingress to connect to the HTTP listener, and have in-namespace pods connect to the HTTPS listener using a certificate trusted by those pods.

```bash
./bin/vault-server \
  --addr 0.0.0.0:8200 \
  --http-addr 0.0.0.0:8201 \
  --db /var/lib/vault/vault.db \
  --tls-cert /etc/vault/tls/server.crt \
  --tls-key /etc/vault/tls/server.key
```

For Kubernetes, expose port `8201` to the ingress for management and backup traffic, and port `8200` for pod-to-pod HTTPS traffic. Both listeners serve the same endpoints and share the same application state. Keep the HTTP listener on a private network and do not expose it directly to untrusted clients.

Recommended deployment controls:

- Run behind a firewall or private network
- Restrict database and key files to mode `0600`
- Use an encrypted persistent volume
- Back up `vault.db`, `vault.db.key`, and `vault.db.setup-key`
- Keep `vault.db.key` available and protected; it is required to open newly created encrypted databases
- Use a TLS reverse proxy or load balancer if needed
- Rotate API tokens and certificates periodically

## API authentication

External API endpoints use `/api` and token authentication:

```bash
# Authenticate
curl --cacert /path/to/ca.pem \
  -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"password":"your-password"}' \
  https://localhost:8200/api/v1/auth/ldap/login/admin

# Read a KV secret
curl --cacert /path/to/ca.pem \
  -H 'X-Vault-Token: TOKEN' \
  https://localhost:8200/api/v1/kv/data/app/database
```

Web routes such as `/`, `/v1/setup`, `/v1/auth/login`, and `/v1/secrets/...` use an HttpOnly session cookie.

## Test

From the repository root:

```bash
./tests/test-vault-server.sh
```

The integration test creates a temporary HTTPS certificate, starts isolated HTTP and HTTPS listeners, and cleans up its data automatically.

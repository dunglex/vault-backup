# Vault Backup and Vault Server

This repository contains:

- `vault-backup`: a CLI for exporting Vault KV secrets to files and restoring files into Vault
- `vault-server`: a small HTTPS-only SQLite-backed Vault-compatible server

## Requirements

- Go 1.26 or later
- `mkcert` for trusted local HTTPS development
- OpenSSL for generated test certificates

## Local HTTPS development with mkcert

Install and initialize mkcert:

```bash
# Linux
sudo apt install mkcert
mkcert -install

# macOS
brew install mkcert
mkcert -install
```

Generate localhost certificates:

```bash
mkdir -p tests/data
cd tests/data
mkcert -cert-file localhost.pem -key-file localhost-key.pem localhost 127.0.0.1 ::1
cd ../..
```

Build and start the server:

```bash
./build.sh
./tests/start-vault-server.sh
```

Open:

```text
https://localhost:8200/
```

The startup script uses `tests/data/vault.db`, `tests/data/vault.db.key`, and `tests/data/vault.db.setup-key`.

## HTTPS startup options

HTTPS is mandatory. The server exits unless both a certificate and private key are supplied:

```bash
./bin/vault-server \
  --addr 127.0.0.1:8200 \
  --db /secure/location/vault.db \
  --tls-cert /secure/location/localhost.pem \
  --tls-key /secure/location/localhost-key.pem
```

Environment variables are also supported:

```bash
export VAULT_SERVER_ADDR=127.0.0.1:8200
export VAULT_SERVER_DB=/secure/location/vault.db
export VAULT_SERVER_TLS_CERT=/secure/location/server.crt
export VAULT_SERVER_TLS_KEY=/secure/location/server.key
./bin/vault-server
```

## Production deployment

Use certificates issued by a trusted certificate authority. Do not deploy HTTP-only or use `--insecure`.

```bash
./bin/vault-server \
  --addr 0.0.0.0:8200 \
  --db /var/lib/vault/vault.db \
  --tls-cert /etc/vault/tls/server.crt \
  --tls-key /etc/vault/tls/server.key
```

Recommended deployment controls:

- Run behind a firewall or private network
- Restrict database and key files to mode `0600`
- Use an encrypted persistent volume
- Back up `vault.db`, `vault.db.key`, and `vault.db.setup-key`
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

## Container images

```bash
NOPUSH=true ./build-image.sh
```

Run the server over HTTPS:

```bash
podman run --rm \
  -p 8200:8200 \
  -v "$PWD/tests/data:/data" \
  registry.vn.eit.zone/hr-digi/vault-server:latest \
  --addr 0.0.0.0:8200 \
  --db /data/vault.db \
  --tls-cert /data/localhost.pem \
  --tls-key /data/localhost-key.pem
```

## Tests

```bash
./tests/test-vault-server.sh
./tests/test-vault-backup.sh
```

Both scripts create temporary HTTPS certificates, start isolated servers, and clean up their data automatically.

# vault-server

`vault-server` is a SQLite-backed Vault-compatible server. HTTPS is the default transport. Application data and secret values are stored in separate SQLCipher databases, each with its own random key protected by the configured database password. Existing plaintext SQLite application databases are rejected unless explicitly allowed with the plaintext opt-in; that mode is insecure. This version does not migrate secrets from an older application database that still contains a `secrets` table. Existing single-value secrets databases are migrated to version 1 at startup.

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

The startup script uses `tests/data/vault.db`, `tests/data/vault.db.key`, and generates a setup key only until the first account is created.

An unconfigured server allows initial administrator setup for 20 minutes. The setup window is stored in the database, so restarting the server does not reset it. After expiry, the setup page returns `423 Locked` until an administrator resets the unconfigured server's database state.

First-run setup has five phases: validate the setup key, optionally configure
domains and the server certificate, create the Admin account, select optional
app extensions, and continue to the login page. Skipping domain configuration
keeps the current domain and certificate settings. When Operators is selected,
setup initializes its encrypted operator database at the default
`*-operators.db` path beside the main database; an explicitly configured
`--operator-db` or `VAULT_SERVER_OPERATOR_DB` database remains in use.
Selecting Backup enables the `/backup.html` menu for scheduled backups,
on-demand archives, and restoring server data archives.

The initial account has the **Admin** role. The default installation is
administrator-only: operator routes and accounts are disabled unless Operators
is enabled during setup or an operator database is configured with `--operator-db` or
`VAULT_SERVER_OPERATOR_DB`. The configured database is encrypted and uses its
own protected key file. Admins can then create, lock, unlock, reset two-factor
authentication for, and remove Operator accounts from `/operators.html`.
Locking an Operator blocks login and revokes their active web sessions.
Resetting two-factor authentication clears their TOTP setup and recovery codes
and revokes active sessions; when MFA enforcement is enabled, the Operator must
enroll again before continuing. Operators can manage secrets, API tokens, and
audit events within their assigned secret path prefixes. Their audit views
include only resource paths that overlap their current prefixes, plus their
own web secret-list events. Admins retain unrestricted audit access. Filtering
uses the Operator's current account prefixes at query time; audit records do
not duplicate role or account-scope data.
Operators cannot access `/security.html`,
`/v1/settings`, `/operators.html`, or operator-management endpoints.
Admin accounts retain unrestricted web access. Admins assign one or more
prefixes when creating an Operator and can change them later from
`/operators.html`. Existing Operators are migrated without prefixes and need an
Admin to assign them before they can access secrets. Each account or token can
have up to 100 prefixes. A prefix grants access to
the exact path and its descendants at segment boundaries; for example, `team-a`
covers `team-a/database`, but not `team-archive`. Prefixes use the same path
validation as secrets. The API mount is a routing component, not part of a
secret's path: `team-a` grants access to `team-a/database` through
`/api/v1/kv/data/team-a/database`. All mounts share the same secret-path
namespace, so the same path through another mount refers to the same secret.
Operators with no configured prefixes cannot access secrets.
Creating an Operator generates a random 12-20 character temporary password
shown only once in the admin dialog. Copy or record it before closing the
dialog, then provide it to the Operator through a secure channel. The Operator
must change this password after their first web login; access to other
application features is blocked until the change is complete. LDAP-compatible
login is unavailable until the temporary password has been changed through
the web interface.
Admins can reset an existing Operator's password from `/operators.html`.
Resetting revokes active sessions, shows a new 12-20 character temporary
password once, and requires the Operator to change it at their next web login.

Two-factor authentication with TOTP is optional and disabled by default for
each account. Users can change their password, enroll TOTP, and disable it from
`/account.html`; setup displays a local QR code or the secret for manual entry.
Recovery codes are shown once when TOTP is enabled. Users can generate and
display a replacement set from their account page by confirming their password
and second factor; this invalidates all previous recovery codes. Once enabled,
web and LDAP-compatible logins require an authenticator code or an unused
recovery code. TOTP secrets and recovery-code hashes are stored in the encrypted account
database: the main database for Admin accounts, and the optional operator
database for Operator accounts.

Admins can enable **Enforce MFA for all users** in `/security.html`; it is
disabled by default when no setting has been saved. Existing explicit settings
are preserved across upgrades. Users without enrolled TOTP are restricted to their
account page and MFA enrollment until setup is complete. LDAP-compatible login
cannot issue a client token for an unenrolled account. Once enrolled, users
must complete TOTP or recovery-code verification at every web and
LDAP-compatible login. MFA cannot be disabled while enforcement is active.

Web session cookies last 30 minutes for accounts without TOTP and 8 hours
after a successful TOTP or recovery-code login. The session duration is chosen
at login, so an account that just enabled TOTP receives the longer duration on
its next sign-in. Session records are stored in the encrypted account database
with only a hash of each cookie token, so valid sessions survive server
restarts. Admin sessions are in the main database; Operator sessions are in
the optional operator database. Logging out removes the persistent session;
inactive or expired sessions are rejected and cleaned up.

When an existing application database contains Operator accounts, starting
with `--operator-db` migrates those accounts and their valid sessions to the
separate encrypted database. Without that option, legacy Operator accounts are
left in the old encrypted database but are not available for login or
management. Configure the operator database to migrate and re-enable them.

## Configuration from .env

By default, the server loads `.env` from the current working directory. Existing process environment variables take precedence over values in the file:

```dotenv
VAULT_SERVER_DB_PASSWORD=use-a-long-random-password
VAULT_SERVER_HTTPS_ADDR=127.0.0.1:8200
VAULT_SERVER_HTTP_ADDR=
VAULT_SERVER_DB=/var/lib/vault/vault.db
VAULT_SERVER_SECRETS_DB=/var/lib/vault/vault-secrets.db
VAULT_SERVER_AUDIT_DB=/var/lib/vault/audit.db
# Optional: enables Operator accounts in a separate encrypted database.
# This path can also be named team.db if it will hold future team data.
# VAULT_SERVER_OPERATOR_DB=/var/lib/vault/operator.db
VAULT_SERVER_DATA_DIR=/var/lib/vault
VAULT_SERVER_BACKUP_DIR=/backup
VAULT_SERVER_TLS_CERT=/etc/vault/tls/server.crt
VAULT_SERVER_TLS_KEY=/etc/vault/tls/server.key
VAULT_SERVER_TRUSTED_PROXIES=10.0.0.0/8
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
The application and secrets databases each have a separate protected key file:
`vault.db.key` and `vault-secrets.db.key`. When the optional operator database
is configured, it also has a separate `operator.db.key`. Each key is wrapped
using the configured database password. Operator database files and key files
should be stored inside the data directory to include them in scheduled
backups.

Security events are stored separately in plaintext SQLite audit databases. The
`--audit-db` or `VAULT_SERVER_AUDIT_DB` value is the database base path; for
`audit.db`, yearly files are named `audit-YYYY.db` alongside the main database.
The current UTC year's database accepts writes. Previous years are checkpointed
and made read-only, and the audit page searches one selected year at a time.
On first startup after upgrading, records in the old single `audit.db` are
migrated to their UTC-year files and that legacy database is retained read-only.
Audit databases store event metadata only, never secret values or raw tokens.

HTTP access logs and server error logs are written to standard output by default.
Admins can enable **Also write access and error logs to files** on the Security
page; file logging is disabled by default and duplicates the stdout logs. Files
are written to `logs/vault-server-YYYY-MM-DD.log` under the server's working
directory, rotated daily, restricted to mode `0600`, and cleaned up after seven
days. The `logs` directory is created with mode `0700` when needed. Access logs
record the request path but omit query strings.

Web and LDAP-compatible username/password endpoints apply a cryptographically
random 3-5 second delay before credential verification for attempts admitted
by their shared limit of five per ten minutes, applied to both the client IP
and account. By default,
forwarding headers are ignored. If the server is behind a reverse proxy,
configure `--trusted-proxies` or `VAULT_SERVER_TRUSTED_PROXIES` with the exact
proxy IPs or CIDRs; only those peers may supply `X-Forwarded-For` or
`X-Forwarded-Proto`. The proxy should preserve the external `Host`.

The Security page also offers **Auto block login bruteforce IP**, disabled by
default. When enabled, five failed logins from the same client IP within ten
minutes create a permanent block shared by web and LDAP-compatible login.
Successful logins clear that IP's pending failure sequence. The **View blocked
IPs** dialog lists permanent blocks; disabling the option stops enforcing them
but does not remove stored blocks. Admins can unblock addresses from the dialog;
automatic blocks, blocked login attempts, and manual unblocks are written to the
audit log. Configure trusted proxies carefully so the server can identify the
actual client IP.

After setup, requests are served only when the `Host` and, when present, `Origin` use the configured main or alias domain. Health probes and the setup flow are exempt so probes and initial setup continue to work. These checks are not authentication: non-browser clients can forge these headers, so protected operations still require their normal credentials.

On `SIGINT` or `SIGTERM`, the server stops accepting new connections, drains active requests for up to 15 seconds, closes all listeners, and then closes the encrypted database connection.

## Back up server state

Administrators can enable scheduled backups from the Security page. The
six-field cron expression uses UTC and defaults to `0 0 2 * * *` (daily at
02:00). The Security page describes the entered schedule as it changes; the
server validates it when settings are saved. Each run serves a maintenance page,
waits for active requests to drain,
closes the application, secrets, optional operator, and audit database handles, archives the
configured data directory, then reopens the databases. Archives are gzip tar
files with SHA-256 manifests, mode `0600`, and are stored in the configured
backup directory. Files older than 30 days are removed after a successful
backup. Data and backup directories can be set with `--data-dir` /
`VAULT_SERVER_DATA_DIR` and `--backup-dir` / `VAULT_SERVER_BACKUP_DIR`. If the
backup directory is omitted, it defaults to a sibling of the data directory
(for example, `/backup` when the data directory is `/data`).
Files stored outside the data directory must be backed up separately.

The restore refuses to overwrite a non-empty destination unless `--replace` is specified. It verifies SHA-256 checksums before installing files with restricted permissions.

## Managed API tokens

After logging in through the web UI at `/tokens.html`, an admin or enabled operator can
create tokens in the add-token dialog, list, and revoke API tokens. Each token
requires one or more secret path prefixes and can read, write, delete, and list
only within those prefixes. Prefixes use the secret path format described above.
Operators may create tokens only for paths within their own assigned prefixes;
their tokens remain bounded by the Operator's current prefixes. Admins enter
token prefixes directly; Operators choose from the prefixes assigned to them by
an Admin. The server rejects out-of-scope prefixes even if an Operator bypasses
the web form. Tokens with no configured prefixes, including existing tokens
after upgrade, cannot access secrets until an Admin assigns prefixes.
Tokens:

- Must have a unique name
- Default to a 30-day lifetime; choose between 1 and 365 days when creating one
- Never outlive the one-year maximum
- Are shown only in the creation response
- Are stored as SHA-256 hashes in the encrypted database

Client certificates are issued only while mutual TLS enforcement is enabled.
When enabled, token creation also returns a token-bound certificate and private
key with the same expiry as the token. When disabled, creation returns the API
token only. Each private key is downloadable only in its issuance response.
The server stores certificate authorization metadata, not the private key. Use
**Issue certificate** or **Replace certificate** on an active token while
enforcement is enabled; replacement immediately revokes the previous
certificate and does not extend the token's expiry. Protect downloaded files as
secrets.

Management endpoints use a web session. When the optional operator database is
enabled, Operators can manage API tokens, but
their token prefixes cannot exceed their own assigned prefixes. Security
settings and operator-management endpoints require the Admin role:

```bash
POST   /v1/tokens
GET    /v1/tokens
PUT    /v1/tokens/{id}/prefixes
POST   /v1/tokens/{id}/certificate
DELETE /v1/tokens/{id}
GET    /v1/settings
PUT    /v1/settings
GET    /v1/settings/blocked-login-ips
DELETE /v1/settings/blocked-login-ips/{ip}
GET    /v1/backup/settings            (backup extension required)
PUT    /v1/backup/settings            (backup extension required)
GET    /v1/backup                     (backup extension required)
POST   /v1/backup                     (backup extension required)
POST   /v1/backup/restore             (backup extension required)
POST   /v1/backup/s3/test             (backup extension required)
GET    /v1/operators                 (operator database required)
GET    /v1/operators/details         (operator database required)
POST   /v1/operators                 (operator database required)
PUT    /v1/operators/prefixes        (operator database required)
DELETE /v1/operators                 (operator database required)
POST   /v1/operators/password        (operator database required)
PATCH  /v1/operators/lock            (operator database required)
DELETE /v1/operators/totp            (operator database required)
GET    /v1/account/totp
POST   /v1/account/totp/setup
POST   /v1/account/totp/enable
POST   /v1/account/totp/recovery-codes
DELETE /v1/account/totp
POST   /v1/account/password
```

Server backup archives include a `vault-server/metadata.json` entry with their
creation time and operator, secret, and API token counts. The admin-only
`GET /v1/backup` endpoint lists these summaries; archives
created before metadata was added are listed with counts shown as unavailable.
When the Backup extension is enabled, `/backup.html` can configure optional
S3 copies. S3 settings include endpoint, region, bucket, key prefix, access
key ID, secret access key, optional session token, and path-style addressing.
S3 copy is disabled by default. After a local archive is created successfully,
the server uploads it to the configured bucket and object key prefix.
`POST /v1/backup/s3/test` verifies the saved or submitted S3 configuration.

Create a token:

```bash
curl --cookie cookies.txt \
  -H 'Content-Type: application/json' \
  -d '{"name":"backup-agent","expires_in_days":365}' \
  https://vault.example:8200/v1/tokens
```

`expires_in_days` is optional (defaults to 30) and must be from 1 to 365. The
response includes client credentials only when mTLS enforcement is enabled;
the certificate expires at the same time as its token.
Token names are trimmed and must be unique; creating a duplicate name returns
HTTP 409.

Use managed API tokens through `X-Vault-Token` or the `Authorization: Bearer` header. Username/password login tokens and browser cookies do not authorize `/api/...` endpoints.

## Mutual TLS

The admin UI at `/security.html` provides a persistent switch:

- **Enforce mutual TLS for Vault API clients** requires a valid managed
  certificate on `/api/...` requests. The certificate must be associated with
  the presented managed API token. Admin pages and `/health` remain accessible
  without a client certificate. Enforced API requests must use HTTPS; a
  TLS-terminating proxy must use TLS passthrough or HTTPS to the server. Older
  `vault-backup` binaries are rejected until upgraded.

The token's client certificate expires at the same time as the token, with a
maximum lifetime of one year. Replacing a certificate does not extend token
life; create a replacement token and certificate before expiry. Newer clients
send a required protocol marker when enforcement is enabled.
This rejects older CLI versions, but a custom client can imitate that marker;
it is a compatibility gate, not proof of executable integrity.

Enabling enforcement immediately rejects API calls that lack a valid
certificate and matching token. Once enabled, create a managed API token from
`/tokens.html` and download its certificate and private key from the creation
dialog, or use **Issue certificate** for an existing token. The private key is
delivered over HTTPS and is not available for later download. Then run:

```bash
VAULT_TOKEN="$VAULT_API_TOKEN" ./bin/vault-backup \
  --url https://vault.example:8200/api \
  --token "$VAULT_TOKEN" \
  --ca_cert /path/to/vault-server-ca.pem \
  --client_cert ./vault-client-cert.pem \
  --client_key ./vault-client-key.pem \
  --secret_name kv \
  --secret_path app/database \
  --output_mode file \
  --output_format env \
  --output_path ./database.env
```

After downloading the key files, restrict their permissions:

```bash
chmod 600 ./vault-client-cert.pem ./vault-client-key.pem
```

`--ca_cert` verifies the Vault **server** certificate. The downloaded client
certificate authenticates the CLI to the Vault API; do not use `--insecure`.
The managed client CA and its encrypted signing key are stored in the encrypted
Vault database and are preserved by the normal server database backup.

The separate `VAULT_SERVER_MTLS_CA_CERT` startup option retains its existing
behavior: it requires certificates for every HTTPS connection, including web
pages and health checks.

For static listener-wide mTLS, configure a PEM-encoded CA bundle containing
the certificates that may authenticate Vault clients:

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

The server starts only HTTPS by default. TLS certificate and key flags are optional, but must be provided together when used. If omitted, the server creates a self-signed bootstrap certificate and stores it as `server.crt` and `server.key` alongside the database. The optional domain-configuration phase of first-run setup collects the main and alias domains and replaces this certificate with one covering those names. An existing supplied certificate pair is never overwritten.

The setup page offers self-signed certificates or ACME/Let's Encrypt. ACME is available when the HTTP listener is enabled and requires public DNS for each name plus public HTTP access on port 80. ACME issues a certificate for the main domain during setup and for each alias on its first HTTPS connection; the certificates are automatically renewed and stored in an `acme-cache` directory alongside the database. The server persists the domain list and selected certificate mode in the encrypted database.

HTTP is opt-in: set `--http-addr` or `VAULT_SERVER_HTTP_ADDR` explicitly; starting HTTP prints an insecure-awareness warning:

```bash
./bin/vault-server \
  --https-addr 127.0.0.1:8200 \
  --http-addr 127.0.0.1:8201 \
  --db /secure/location/vault.db \
  --tls-cert /secure/location/localhost.pem \
  --tls-key /secure/location/localhost-key.pem
```

Environment variables are also supported:

```bash
export VAULT_SERVER_HTTPS_ADDR=127.0.0.1:8200
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

For production, choose ACME during first-run setup or provide a certificate pair issued by a trusted certificate authority. Configure the ingress to connect to the HTTP listener, and have in-namespace pods connect to the HTTPS listener using a certificate trusted by those pods.

```bash
./bin/vault-server \
  --https-addr 0.0.0.0:8200 \
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
- Back up `vault.db` and `vault.db.key`
- Keep `vault.db.key` available and protected; it is required to open newly created encrypted databases
- Use a TLS reverse proxy or load balancer if needed
- Rotate API tokens and certificates periodically

## API authentication

External API endpoints use `/api` and token authentication:

```bash
# Read a KV secret
curl --cacert /path/to/ca.pem \
  -H 'X-Vault-Token: MANAGED_API_TOKEN' \
  https://localhost:8200/api/v1/kv/data/app/database

# Write a new immutable version; CAS 0 means the path must not exist
curl --cacert /path/to/ca.pem \
  -H 'X-Vault-Token: MANAGED_API_TOKEN' \
  -H 'Content-Type: application/json' \
  -X PUT -d '{"data":{"username":"app","password":"secret"},"options":{"cas":0}}' \
  https://localhost:8200/api/v1/kv/data/app/database

# Read a specific version and inspect version metadata
curl --cacert /path/to/ca.pem -H 'X-Vault-Token: MANAGED_API_TOKEN' \
  'https://localhost:8200/api/v1/kv/data/app/database?version=1'
curl --cacert /path/to/ca.pem -H 'X-Vault-Token: MANAGED_API_TOKEN' \
  https://localhost:8200/api/v1/kv/metadata/app/database

# Soft-delete, restore, or permanently destroy selected versions
curl --cacert /path/to/ca.pem -H 'X-Vault-Token: MANAGED_API_TOKEN' \
  -X DELETE https://localhost:8200/api/v1/kv/data/app/database
curl --cacert /path/to/ca.pem -H 'X-Vault-Token: MANAGED_API_TOKEN' \
  -H 'Content-Type: application/json' -X POST -d '{"versions":[1]}' \
  https://localhost:8200/api/v1/kv/undelete/app/database
```

Web routes such as `/`, `/v1/setup`, `/v1/auth/login`, and `/v1/secrets/...` use an HttpOnly session cookie.

Open `/secrets.html` to browse secrets grouped by their first two path segments. Each group is paginated independently, and selecting a secret opens it in the editor at `/secret.html`. The editor shows the current version and a version selector; older versions are read-only, while selecting the current version enables editing. The editor breadcrumb links back to each ancestor path; nested prefixes open a filtered secret list.
Secret path segments are 1–127 characters and may contain only ASCII letters, digits, and hyphens. Underscores and dots are rejected. Full paths remain unique by the primary database key.

Each successful write creates a monotonically increasing version; prior versions are retained. The API accepts `options.cas` on writes (`0` means create-only; a positive value must match the current version) and accepts `?version=N` on reads. `DELETE /data/{path}` soft-deletes the current version. Use `POST /delete/{path}`, `POST /undelete/{path}`, and `POST /destroy/{path}` with `{"versions":[N,...]}` to manage selected versions. Destroying a version clears its ciphertext from the active database and cannot be undone through the API; this operation requires a token created by an active administrator. Database backups or SQLite WAL files created before destruction may still contain the prior encrypted data. Version metadata is available from `GET /metadata/{path}`. These endpoints use the same path scopes as secret reads and writes.

## Audit log

Authenticated administrators can open `/audits.html` to search and filter successful and failed login events, secret list/read/create/update/delete activity from both the web panel and managed-token `/api/...` endpoints, and managed API token creation/revocation. Token audit events contain token record IDs, never raw token values. API token identities are recorded as truncated SHA-256 fingerprints. Filters cover text, actor, source, action, outcome, and date range. The backing `/v1/audit` endpoint uses the web session cookie and is limited to 500 events per response.

## Test

From the repository root:

```bash
python3 ./tests/test_vault_server.py
```

The integration test creates a temporary HTTPS certificate, starts isolated HTTP and HTTPS listeners, and cleans up its data automatically.

To populate a running server with dummy secrets, create a managed API token in the web panel and run:

```bash
python3 ./generate_dummy_secrets.py \
  --count 1000 \
  --prefix apps/production \
  --prefix databases/postgres \
  --prefix teams/platform

./scripts/build.sh
VAULT_URL=https://vault.example:8200/api \
VAULT_TOKEN="$VAULT_API_TOKEN" \
python3 ./restore_dummy_secrets.py
```

The generator writes JSON files into `test_data/`; their paths become Vault
secret paths. The restore helper uses `bin/vault-backup` to restore them. Use
`--insecure-tls` only for trusted development certificates, or specify
`--ca-cert` for the server CA.

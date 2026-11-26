# Scripts

| Tool | Purpose | Example |
| --- | --- | --- |
| `build.sh` | Builds `mkcert`, `vault-backup`, and `vault-server` into `bin/`; builds the server with SQLite FTS5, JSON1, and secure-delete support; records output in `logs/build.log`. | `./scripts/build.sh` |
| `build-image.sh` | Builds a `linux/amd64` container image with Podman (default) or Docker. | `BUILDER=podman NOPUSH=true ./scripts/build-image.sh` |
| `start-vault-server.sh` | Starts a local HTTPS server using certificates and database files under `data/`. | `./scripts/start-vault-server.sh` |
| `restore-vault-server.sh` | Restores a backup archive into a clean data directory. | `./scripts/restore-vault-server.sh --data-dir /data backup.tar.gz` |

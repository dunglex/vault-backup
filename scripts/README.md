# Scripts

| Script | Purpose | Example |
| --- | --- | --- |
| `build.sh` | Builds `mkcert`, `vault-backup`, and `vault-server` into `bin/`. | `./scripts/build.sh` |
| `build-image.sh` | Builds a `linux/amd64` container image with Podman (default) or Docker. | `BUILDER=podman NOPUSH=true ./scripts/build-image.sh` |
| `start-vault-server.sh` | Starts a local HTTPS server using certificates and database files under `data/`. | `./scripts/start-vault-server.sh` |
| `backup-vault-server.sh` | Creates a timestamped backup archive under `backups/`. | `./scripts/backup-vault-server.sh --db /var/lib/vault/vault.db --output /secure/backups/vault-server.tar.gz` |
| `restore-vault-server.sh` | Restores a backup archive into a clean data directory. | `./scripts/restore-vault-server.sh --data-dir /data backup.tar.gz` |

Use `--help` to see options for the backup and restore scripts:

```bash
./scripts/backup-vault-server.sh --help
./scripts/restore-vault-server.sh --help
```

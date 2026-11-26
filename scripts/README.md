# Scripts

| Tool | Purpose | Example |
| --- | --- | --- |
| `build.sh` | Builds `mkcert`, `vault-backup`, and `vault-server` into `bin/`. | `./scripts/build.sh` |
| `build-image.sh` | Builds a `linux/amd64` container image with Podman (default) or Docker. | `BUILDER=podman NOPUSH=true ./scripts/build-image.sh` |
| `start-vault-server.sh` | Starts a local HTTPS server using certificates and database files under `data/`. | `./scripts/start-vault-server.sh` |
| `restore-vault-server.sh` | Restores a backup archive into a clean data directory. | `./scripts/restore-vault-server.sh --data-dir /data backup.tar.gz` |

Scheduled server backups are configured by an administrator on the Security page.
Use `--help` to see options for the restore script:

```bash
./scripts/restore-vault-server.sh --help
```

The restore script requires Bash, Python 3, and GNU tar to validate and extract backup archives. These are not included in the server runtime image.

#!/usr/bin/env python3
import os
import signal
import stat
import subprocess
import tarfile
import time

from test_common import HttpClient, ServerTest, assert_status, require, run


def mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def main() -> None:
    with ServerTest(18228, 18229) as server:
        require(mode(server.path / "vault.db") == 0o600, "database permissions")
        print("PASS: database file permissions")
        require(not (server.path / "vault.db").read_bytes().startswith(b"SQLite format 3\0"), "database is plaintext")
        print("PASS: database file is encrypted")
        require(mode(server.path / "vault.db.key") == 0o600, "key permissions")
        print("PASS: encryption key file permissions")
        require(mode(server.path / "vault-secrets.db") == 0o600, "secrets database permissions")
        require(
            not (server.path / "vault-secrets.db").read_bytes().startswith(b"SQLite format 3\0"),
            "secrets database is plaintext",
        )
        require(mode(server.path / "vault-secrets.db.key") == 0o600, "secrets key permissions")
        print("PASS: separate secrets database is encrypted")
        audit_path = server.path / f"audit-{time.gmtime().tm_year}.db"
        require(mode(audit_path) == 0o600, "audit database permissions")
        require(audit_path.read_bytes().startswith(b"SQLite format 3\0"), "audit database is not plaintext")
        print("PASS: separate plaintext audit database")

        server.setup()
        server.login()
        status, years = server.client.json(
            "GET", f"{server.https_url}/v1/audit/years"
        )
        assert_status(200, status, "list audit years")
        require(
            time.gmtime().tm_year in years["years"],
            "current UTC year missing from audit year list",
        )
        status, _ = server.client.json(
            "PUT",
            f"{server.https_url}/v1/secrets/restore-test/database",
            data={"data": {"username": "restore-admin", "password": "restore-secret"}},
        )
        assert_status(200, status, "create secret for database restore")
        status, _ = server.client.json(
            "GET",
            f"{server.https_url}/v1/audit?year={time.gmtime().tm_year - 1}",
        )
        assert_status(400, status, "reject unavailable audit year")
        status, _ = server.client.json(
            "GET",
            f"{server.https_url}/v1/audit?year={time.gmtime().tm_year}&from={time.gmtime().tm_year - 1}-12-31",
        )
        assert_status(400, status, "reject date filter outside selected audit year")

        status, settings = server.client.json(
            "PUT",
            f"{server.https_url}/v1/settings",
            data={
                "automatic_server_backup": True,
                "server_backup_cron": "*/2 * * * * *",
            },
        )
        assert_status(200, status, "enable scheduled server backups")
        require(settings["automatic_server_backup"], "automatic backups were not enabled")
        require(settings["server_backup_cron"] == "*/2 * * * * *", "cron schedule was not saved")
        print("PASS: save six-field backup schedule")

        backup_dir = server.path / "backups"
        for _ in range(80):
            archives = sorted(backup_dir.glob("vault-server-backup-*.tar.gz")) if backup_dir.exists() else []
            if archives:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("scheduled server backup was not created")
        archive = archives[-1]
        require(mode(archive) == 0o600, "backup archive permissions")
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
            require("vault-server/data/vault.db" in names, "server backup omitted main database")
            require("vault-server/data/vault.db.key" in names, "server backup omitted protected database key")
            require("vault-server/data/vault-secrets.db" in names, "server backup omitted secrets database")
            require("vault-server/data/vault-secrets.db.key" in names, "server backup omitted secrets key")
            require(
                any(name.startswith("vault-server/data/audit-") and name.endswith(".db") for name in names),
                "server backup omitted annual audit database",
            )
            require("vault-server/manifest.txt" in names, "server backup omitted SHA-256 manifest")
        print("PASS: scheduler creates complete protected archive")

        for _ in range(20):
            status, health = server.client.json("GET", f"{server.https_url}/health")
            if status == 200 and health["ok"]:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("server did not resume after scheduled backup")
        print("PASS: server resumes after maintenance backup")
        status, settings = server.client.json("GET", f"{server.https_url}/v1/settings")
        assert_status(200, status, "read scheduled backup completion time")
        require(settings["server_backup_last_success"], "backup completion time was not saved")
        _, audit = server.client.json("GET", f"{server.https_url}/v1/audit")
        require(
            any(event["action"] == "server_backup" and event["outcome"] == "started" for event in audit["events"])
            and any(event["action"] == "server_backup" and event["outcome"] == "success" for event in audit["events"]),
            "backup start and success were not audited",
        )
        print("PASS: save backup completion time and audit start/success")
        server.stop()

        restore_dir = server.path / "restored-data"
        run(
            "./scripts/restore-vault-server.sh",
            "--data-dir",
            restore_dir,
            archive,
        )
        require(mode(restore_dir / "vault.db") == 0o600, "restored database permissions")
        require(mode(restore_dir / "vault.db.key") == 0o600, "restored key permissions")
        require(mode(restore_dir / "vault-secrets.db") == 0o600, "restored secrets database permissions")
        require(mode(restore_dir / "vault-secrets.db.key") == 0o600, "restored secrets key permissions")
        print("PASS: restore installs protected database files")

        restored_port = 18230
        restored_url = f"https://127.0.0.1:{restored_port}"
        restored_env = os.environ | {
            "VAULT_SERVER_HTTPS_ADDR": f"127.0.0.1:{restored_port}",
            "VAULT_SERVER_HTTP_ADDR": "",
            "VAULT_SERVER_DB": str(restore_dir / "vault.db"),
            "VAULT_SERVER_SECRETS_DB": str(restore_dir / "vault-secrets.db"),
            "VAULT_SERVER_AUDIT_DB": str(restore_dir / "audit.db"),
            "VAULT_SERVER_DB_PASSWORD": server.password,
        }
        restored_log = open(server.path / "restored-server.log", "wb")
        restored_process = subprocess.Popen(
            [
                str(server.server_binary),
                "--tls-cert",
                str(restore_dir / "test-cert.pem"),
                "--tls-key",
                str(restore_dir / "test-key.pem"),
            ],
            cwd=server.path,
            env=restored_env,
            stdout=restored_log,
            stderr=subprocess.STDOUT,
        )
        try:
            restored_client = HttpClient()
            for _ in range(40):
                if restored_process.poll() is not None:
                    raise RuntimeError(
                        (server.path / "restored-server.log").read_text(errors="replace")
                    )
                status, _ = restored_client.request(
                    "GET", f"{restored_url}/health", timeout=1
                )
                if status == 200:
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("restored server did not become healthy")

            for _ in range(120):
                status, _ = restored_client.json(
                    "POST",
                    f"{restored_url}/v1/auth/login",
                    data={"username": server.user, "password": server.password},
                )
                if status != 503:
                    break
                time.sleep(0.25)
            assert_status(200, status, "log in to restored server")
            for _ in range(120):
                status, secret = restored_client.json(
                    "GET", f"{restored_url}/v1/secrets/restore-test/database"
                )
                if status != 503:
                    break
                time.sleep(0.25)
            assert_status(200, status, "read secret from restored database")
            require(
                secret["data"] == {
                    "username": "restore-admin",
                    "password": "restore-secret",
                },
                "restored database secret values",
            )
            _, audit = restored_client.json(
                "GET",
                f"{restored_url}/v1/audit?year={time.gmtime().tm_year}&action=create&q=restore-test",
            )
            require(
                any(
                    event["action"] == "create"
                    and event["resource"] == "restore-test/database"
                    for event in audit["events"]
                ),
                "restored audit database event",
            )
            print("PASS: restored server retains audit history")
        finally:
            if restored_process.poll() is None:
                restored_process.send_signal(signal.SIGTERM)
                restored_process.wait(timeout=20)
            restored_log.close()


if __name__ == "__main__":
    main()

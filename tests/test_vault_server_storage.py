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
    with ServerTest(18228, 18229, enable_backup=True) as server:
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
            f"{server.https_url}/v1/backup/settings",
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

        for _ in range(80):
            status, _ = server.client.json(
                "PUT",
                f"{server.https_url}/v1/backup/settings",
                data={"automatic_server_backup": False},
            )
            if status == 200:
                break
            if status != 503:
                assert_status(200, status, "disable rapid scheduled backups")
            time.sleep(0.25)
        else:
            raise RuntimeError("could not disable rapid scheduled backups")

        for _ in range(80):
            status, settings = server.client.json("GET", f"{server.https_url}/v1/backup/settings")
            if status == 200:
                break
            if status != 503:
                assert_status(200, status, "read scheduled backup completion time")
            time.sleep(0.25)
        else:
            raise RuntimeError("could not read backup settings after maintenance")
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


if __name__ == "__main__":
    main()

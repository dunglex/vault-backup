#!/usr/bin/env python3
import stat
import tarfile

from test_common import ServerTest, require, run


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
        require(mode(server.path / "audit.db") == 0o600, "audit database permissions")
        require((server.path / "audit.db").read_bytes().startswith(b"SQLite format 3\0"), "audit database is not plaintext")
        print("PASS: separate plaintext audit database")

        archive = server.path / "vault-server.tar.gz"
        run(
            "./scripts/backup-vault-server.sh",
            "--db",
            server.path / "vault.db",
            "--env-file",
            "",
            "--output",
            archive,
        )
        with tarfile.open(archive, "r:gz") as tar:
            require(
                "vault-server/database/audit.db" in tar.getnames(),
                "server backup omitted audit database",
            )
        print("PASS: server backup includes audit database")


if __name__ == "__main__":
    main()

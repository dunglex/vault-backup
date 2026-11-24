#!/usr/bin/env python3
import stat

from test_common import BackupServerTest, assert_status, require, run


def main() -> None:
    with BackupServerTest() as server:
        status, _ = server.client.json(
            "PUT",
            f"{server.https_url}/api/v1/kv/data/app/database",
            data={"data": {"DATABASE_HOST": "db.example.local", "DATABASE_PORT": "5432", "DATABASE_USER": "backup_admin", "DATABASE_PASSWORD": "s3cr3t"}},
            headers={"Authorization": f"Bearer {server.api_token}"},
        )
        assert_status(200, status, "seed KV v2 source secret")
        output = server.path / "database.env"
        run(
            server.backup_binary,
            "--url",
            server.https_url + "/api",
            "--insecure",
            "--token",
            server.api_token,
            "--secret_name",
            "kv",
            "--secret_path",
            "app/database",
            "--output_mode",
            "file",
            "--output_format",
            "env",
            "--output_path",
            output,
        )
        require(output.exists(), "backup file missing")
        require(stat.S_IMODE(output.stat().st_mode) == 0o600, "backup file permissions")
        content = output.read_text().replace("\r", "")
        for line in [
            "DATABASE_HOST=db.example.local",
            "DATABASE_PORT=5432",
            "DATABASE_USER=backup_admin",
            "DATABASE_PASSWORD=s3cr3t",
        ]:
            require(line in content, f"{line} missing")
        print("PASS: Vault backup produced env file")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from test_common import BackupServerTest, require, run


def main() -> None:
    with BackupServerTest() as server:
        source = server.path / "restored.env"
        source.write_text(
            "DATABASE_HOST=restored.example.local\n"
            "DATABASE_PORT=6432\n"
            "DATABASE_USER=restored_admin\n"
            "DATABASE_PASSWORD=restored-password\n"
        )
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
            "app/restored",
            "--restore",
            "--input_path",
            source,
        )
        _, body = server.client.json(
            "GET",
            f"{server.https_url}/api/v1/kv/data/app/restored",
            headers={"Authorization": f"Bearer {server.api_token}"},
        )
        text = str(body)
        require("restored.example.local" in text and "restored_admin" in text and "restored-password" in text, "restore values")
        print("PASS: env restore wrote secret to Vault")

        directory = server.path / "restore-directory"
        directory.mkdir()
        (directory / "valid.env").write_text("VALUE=partial-restore-succeeded\n")
        (directory / "invalid.json").write_text("{invalid")
        result = run(
            server.backup_binary,
            "--url",
            server.https_url + "/api",
            "--insecure",
            "--token",
            server.api_token,
            "--secret_name",
            "kv",
            "--secret_path",
            "app/batch",
            "--restore",
            "--input_path",
            directory,
            check=False,
        )
        require(result.returncode != 0, "partial restore exited successfully")
        require("invalid.json" in result.stdout + result.stderr, "partial failure not reported")
        _, body = server.client.json(
            "GET",
            f"{server.https_url}/api/v1/kv/data/app/batch/valid",
            headers={"Authorization": f"Bearer {server.api_token}"},
        )
        require("partial-restore-succeeded" in str(body), "successful partial item missing")
        print("PASS: partial directory restore exited unsuccessfully")


if __name__ == "__main__":
    main()

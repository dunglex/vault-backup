#!/usr/bin/env python3
import os

from test_common import BackupServerTest, ROOT, require, run


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

        wrapper_input = server.path / "wrapper-input"
        (wrapper_input / "app").mkdir(parents=True)
        (wrapper_input / "app" / "dummy.json").write_text('{"VALUE":"wrapper-restore"}')
        wrapper_env = os.environ.copy()
        wrapper_env["VAULT_TOKEN"] = server.api_token
        for url in (server.https_url, server.https_url + "/api"):
            run(
                "python3",
                ROOT / "test_data" / "restore_dummy_secrets_with_vault_backup.py",
                "--url",
                url,
                "--input-dir",
                wrapper_input,
                "--binary",
                server.backup_binary,
                "--insecure-tls",
                env=wrapper_env,
            )
            status, body = server.client.json(
                "GET",
                f"{server.https_url}/api/v1/kv/data/app/dummy",
                headers={"Authorization": f"Bearer {server.api_token}"},
            )
            require(status == 200 and body["data"]["data"]["VALUE"] == "wrapper-restore", "wrapper restore")
        print("PASS: wrapper restores using origin and API URLs")


if __name__ == "__main__":
    main()

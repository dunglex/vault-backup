#!/usr/bin/env python3
from test_common import BackupServerTest, run, require


def main() -> None:
    with BackupServerTest() as server:
        result = run(
            server.backup_binary,
            "--url",
            server.https_url + "/api",
            "--token",
            "managed-token",
            "--secret_name",
            "kv",
            "--secret_path",
            "app/database",
            "--output_mode",
            "invalid",
            check=False,
        )
        require(result.returncode == 2, f"invalid config exit {result.returncode}")
        require("output_mode must be one of" in result.stderr, "invalid config message")
        print("PASS: reject invalid CLI configuration before connecting")


if __name__ == "__main__":
    main()

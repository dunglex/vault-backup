#!/usr/bin/env python3
from pathlib import Path
import subprocess

TEST_DIR = Path(__file__).resolve().parent
TESTS = [
    "test_vault_server_health.py",
    "test_vault_server_auth.py",
    "test_vault_server_secrets.py",
    "test_vault_server_api.py",
    "test_vault_server_storage.py",
]


def main() -> None:
    for test in TESTS:
        subprocess.run(["python3", str(TEST_DIR / test)], check=True)
    print("All Vault server integration tests passed.")


if __name__ == "__main__":
    main()

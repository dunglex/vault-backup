#!/usr/bin/env python3
from pathlib import Path
import subprocess

TEST_DIR = Path(__file__).resolve().parent
TESTS = [
    "test_vault_backup_setup.py",
    "test_vault_backup_tls.py",
    "test_vault_backup_seed.py",
    "test_vault_backup_env.py",
    "test_vault_backup_restore.py",
]


def main() -> None:
    for test in TESTS:
        subprocess.run(["python3", str(TEST_DIR / test)], check=True)
    print("All vault-backup integration tests passed.")


if __name__ == "__main__":
    main()

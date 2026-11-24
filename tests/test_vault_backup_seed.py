#!/usr/bin/env python3
from test_common import BackupServerTest, assert_status


def main() -> None:
    with BackupServerTest() as server:
        status, _ = server.client.json(
            "PUT",
            f"{server.https_url}/api/v1/kv/data/app/database",
            data={"data": {"DATABASE_HOST": "db.example.local", "DATABASE_PORT": "5432", "DATABASE_USER": "backup_admin", "DATABASE_PASSWORD": "s3cr3t"}},
            headers={"Authorization": f"Bearer {server.api_token}"},
        )
        assert_status(200, status, "seed KV v2 source secret")


if __name__ == "__main__":
    main()

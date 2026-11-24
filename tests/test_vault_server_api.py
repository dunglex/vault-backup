#!/usr/bin/env python3
from test_common import ServerTest, assert_status


def main() -> None:
    with ServerTest(18226, 18227) as server:
        server.setup()
        server.login()
        status, _ = server.client.request(
            "GET", f"{server.https_url}/api/v1/kv/data/app/database"
        )
        assert_status(401, status, "reject cookie authentication on API endpoints")


if __name__ == "__main__":
    main()

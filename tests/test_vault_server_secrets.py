#!/usr/bin/env python3
from test_common import ServerTest, assert_status, require


def main() -> None:
    with ServerTest(18224, 18225) as server:
        server.setup()
        server.login()

        status, _ = server.client.json(
            "PUT",
            f"{server.https_url}/v1/secrets/app/database",
            data={"data": {"username": "db-admin", "password": "db-password"}},
        )
        assert_status(200, status, "create secret with web cookie")
        _, paths = server.client.json("GET", f"{server.https_url}/v1/secrets")
        require("app/database" in paths, "secret list")
        print("PASS: list secrets with web cookie")

        _, body = server.client.json("GET", f"{server.https_url}/v1/secrets/app/database")
        require(body["data"] == {"username": "db-admin", "password": "db-password"}, "read secret")
        print("PASS: read secret with web cookie")
        status, _ = server.client.json(
            "PUT",
            f"{server.https_url}/v1/secrets/app/database",
            data={"data": {"username": "db-admin", "password": "rotated-password"}},
        )
        assert_status(200, status, "update secret with web cookie")
        _, body = server.client.json("GET", f"{server.https_url}/v1/secrets/app/database")
        require(body["data"]["password"] == "rotated-password", "updated secret")
        print("PASS: verify secret update")
        status, _ = server.client.request("DELETE", f"{server.https_url}/v1/secrets/app/database")
        assert_status(200, status, "delete secret with web cookie")
        status, _ = server.client.request("GET", f"{server.https_url}/v1/secrets/app/database")
        assert_status(404, status, "confirm deleted secret is missing")

        status, page = server.client.request("GET", f"{server.https_url}/audits.html")
        assert_status(200, status, "serve canonical audit page")
        require(b'id="events"' in page, "audit page events table")
        require(b'href="/audits.html"' in page, "canonical audit navigation link")
        status, legacy_page = server.client.request("GET", f"{server.https_url}/audit.html")
        assert_status(200, status, "redirect legacy audit page URL")
        require(b'id="events"' in legacy_page, "legacy audit URL target")
        _, audit = server.client.json("GET", f"{server.https_url}/v1/audit?action=update&q=app%2Fdatabase")
        require(any(e["action"] == "update" and e["resource"] == "app/database" for e in audit["events"]), "filtered audit")
        print("PASS: filter secret CRUD audit events")
        _, audit = server.client.json("GET", f"{server.https_url}/v1/audit")
        require("db-password" not in str(audit) and "rotated-password" not in str(audit), "secret leaked into audit")
        _, deleted = server.client.json("GET", f"{server.https_url}/v1/audit?action=delete")
        require(any(e["action"] == "delete" for e in deleted["events"]), "delete audit")
        print("PASS: audit delete event")
        anonymous = __import__("test_common").HttpClient()
        status, _ = anonymous.request("GET", f"{server.https_url}/v1/audit")
        assert_status(401, status, "reject unauthenticated audit access")

        status, page = server.client.request("GET", f"{server.https_url}/secrets.html")
        assert_status(200, status, "serve grouped secret browser")
        require(b'id="secret-groups"' in page, "browser groups")
        require(b'href="/operators.html"' not in page, "hide operator navigation without the optional database")
        status, _ = server.client.request("GET", f"{server.https_url}/operators.html")
        assert_status(404, status, "keep operator management disabled without the optional database")
        _, browser = server.client.json("GET", f"{server.https_url}/v1/secrets-browser?group=app&limit=1&offset=0")
        require("groups" in browser, "browser response")
        print("PASS: grouped and paginated secret browser")


if __name__ == "__main__":
    main()

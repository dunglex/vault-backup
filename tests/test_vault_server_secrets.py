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
        require(body["version"] == 1, "initial secret version")
        print("PASS: read secret with web cookie")
        status, _ = server.client.json(
            "PUT",
            f"{server.https_url}/v1/secrets/app/database",
            data={"data": {"username": "db-admin", "password": "rotated-password"}},
        )
        assert_status(200, status, "update secret with web cookie")
        _, body = server.client.json("GET", f"{server.https_url}/v1/secrets/app/database")
        require(body["data"]["password"] == "rotated-password" and body["version"] == 2, "updated secret")
        print("PASS: verify secret update")
        _, metadata = server.client.json(
            "GET", f"{server.https_url}/v1/secrets/app/database?metadata=true"
        )
        require(metadata["current_version"] == 2, "current secret version metadata")
        require([version["version"] for version in metadata["versions"]] == [2, 1], "version history")
        _, previous = server.client.json(
            "GET", f"{server.https_url}/v1/secrets/app/database?version=1"
        )
        require(previous["data"]["password"] == "db-password", "read previous secret version")
        print("PASS: inspect and read secret version history")

        api_token, _, _ = server.create_api_token("version-audit")
        api_headers = {"X-Vault-Token": api_token}
        status, api_write = server.client.json(
            "PUT",
            f"{server.https_url}/api/v1/kv/data/app/database",
            headers=api_headers,
            data={
                "data": {"username": "db-admin", "password": "api-password"},
                "options": {"cas": 2},
            },
        )
        assert_status(200, status, "write API secret version")
        require(api_write["data"]["version"] == 3, "API write version")
        status, api_read = server.client.json(
            "GET", f"{server.https_url}/api/v1/kv/data/app/database", headers=api_headers
        )
        assert_status(200, status, "read API secret version")
        require(api_read["data"]["metadata"]["version"] == 3, "API read version")
        status, _ = server.client.request(
            "DELETE", f"{server.https_url}/api/v1/kv/data/app/database", headers=api_headers
        )
        assert_status(204, status, "soft-delete API secret version")
        status, editor = server.client.request("GET", f"{server.https_url}/secret.html")
        assert_status(200, status, "serve secret editor")
        require(
            b'class="secret-editor-heading"' in editor and b'(current)' in editor,
            "secret name and version row",
        )
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
        require(
            any(e["source"] == "web" and e["detail"] == "version=2" for e in audit["events"])
            and any(e["source"] == "api" and e["detail"] == "version=3" for e in audit["events"]),
            "audit update versions for web and API",
        )
        _, reads = server.client.json(
            "GET", f"{server.https_url}/v1/audit?action=read&q=app%2Fdatabase"
        )
        require(
            any(e["source"] == "web" and e["detail"] == "version=1" for e in reads["events"])
            and any(e["source"] == "api" and e["detail"] == "version=3" for e in reads["events"]),
            "audit read versions for web and API",
        )
        print("PASS: filter secret CRUD audit events")
        _, audit = server.client.json("GET", f"{server.https_url}/v1/audit")
        require(
            all(
                secret not in str(audit)
                for secret in ("db-password", "rotated-password", "api-password")
            ),
            "secret leaked into audit",
        )
        _, deleted = server.client.json("GET", f"{server.https_url}/v1/audit?action=delete")
        require(
            any(e["source"] == "web" and e["detail"] == "version=3" for e in deleted["events"])
            and any(e["source"] == "api" and e["detail"] == "version=3" for e in deleted["events"]),
            "audit delete versions for web and API",
        )
        print("PASS: audit delete versions")
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

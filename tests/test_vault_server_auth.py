#!/usr/bin/env python3
from datetime import datetime, timezone

from test_common import ServerTest, assert_status, require


def main() -> None:
    with ServerTest(18222, 18223) as server:
        status, _ = server.client.json(
            "POST",
            f"{server.https_url}/v1/setup",
            data={"setup_key": "wrong", "username": "admin", "password": server.password, "password_confirmation": server.password},
        )
        assert_status(401, status, "reject invalid setup key")
        status, _ = server.client.json(
            "POST",
            f"{server.https_url}/v1/setup",
            data={"setup_key": server.setup_key, "username": "admin", "password": server.password, "password_confirmation": "different-password"},
        )
        assert_status(400, status, "reject mismatched setup passwords")
        server.setup()
        status, _ = server.client.json(
            "POST",
            f"{server.http_url}/v1/setup",
            data={"setup_key": server.setup_key, "username": "other", "password": server.password, "password_confirmation": server.password},
        )
        assert_status(409, status, "disable admin creation after setup")

        login_token = server.login()
        status, _ = server.client.request(
            "GET",
            f"{server.https_url}/api/v1/kv/data/session/test",
            headers={"X-Vault-Token": login_token},
        )
        assert_status(401, status, "reject admin login token on API endpoints")
        status, ldap = server.client.json(
            "PUT",
            f"{server.https_url}/api/v1/auth/ldap/login/admin",
            data={"password": server.password},
        )
        assert_status(200, status, "LDAP-compatible login")
        status, _ = server.client.request(
            "GET",
            f"{server.https_url}/api/v1/kv/data/session/test",
            headers={"Authorization": f"Bearer {ldap['auth']['client_token']}"},
        )
        assert_status(401, status, "reject LDAP login token on API endpoints")

        status, _ = server.client.json(
            "POST",
            f"{server.https_url}/v1/auth/login",
            data={"username": "admin", "password": "wrong-password"},
        )
        assert_status(401, status, "failed login for audit")
        _, audit = server.client.json("GET", f"{server.https_url}/v1/audit?action=login")
        require({e["outcome"] for e in audit["events"]} >= {"success", "failure"}, "login audit outcomes")
        print("PASS: audit successful and failed logins")

        api_token, token_id, token_data = server.create_api_token("backup-agent")
        created = datetime.fromisoformat(token_data["created_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(token_data["expires_at"].replace("Z", "+00:00"))
        require(int((expires - created).total_seconds()) == 2592000, "API token lifetime")
        print("PASS: create fixed-expiry API token")

        api_headers = {"X-Vault-Token": api_token}
        status, _ = server.client.json(
            "PUT",
            f"{server.https_url}/api/v1/kv/data/token/test",
            data={"data": {"managed": "token"}},
            headers=api_headers,
        )
        assert_status(200, status, "authenticate with managed API token")
        status, _ = server.client.request("GET", f"{server.https_url}/api/v1/kv/data/token/test", headers=api_headers)
        assert_status(200, status, "read secret with managed API token")
        status, _ = server.client.json(
            "PUT",
            f"{server.https_url}/api/v1/kv/data/token/test",
            data={"invalid": True},
            headers=api_headers,
        )
        assert_status(400, status, "reject invalid managed API request")
        status, invalid_path = server.client.request(
            "GET", f"{server.https_url}/api/v1/kv/data/invalid_path", headers=api_headers
        )
        assert_status(400, status, "reject invalid API secret path")
        require(b"each segment must be 1-127 characters" in invalid_path, "invalid path error")
        status, _ = server.client.request(
            "LIST", f"{server.https_url}/api/v1/kv/metadata/invalid.path", headers=api_headers
        )
        assert_status(400, status, "reject invalid API metadata path")
        _, audit = server.client.json("GET", f"{server.https_url}/v1/audit?source=api&q=token%2Ftest")
        require({e["action"] for e in audit["events"]} >= {"create", "read"}, "API audit actions")
        require(any(e["outcome"] == "failure" for e in audit["events"]), "API failure audit")
        print("PASS: audit successful and failed managed API operations")

        _, tokens = server.client.json("GET", f"{server.https_url}/v1/tokens")
        require(any(token["name"] == "backup-agent" for token in tokens), "list token")
        print("PASS: list managed API tokens")
        status, _ = server.client.request("DELETE", f"{server.https_url}/v1/tokens/{token_id}")
        assert_status(200, status, "revoke API token")
        status, _ = server.client.request("GET", f"{server.https_url}/api/v1/kv/data/token/test", headers=api_headers)
        assert_status(401, status, "reject revoked API token")

        status, _ = server.client.request("POST", f"{server.https_url}/v1/auth/logout")
        assert_status(200, status, "logout")
        status, _ = server.client.request("GET", f"{server.https_url}/v1/secrets")
        assert_status(401, status, "reject revoked web session")

        attempts = [
            ("POST", server.https_url + "/v1/auth/login", {"username": "admin", "password": "wrong-password"}, 401),
            ("PUT", server.https_url + "/api/v1/auth/ldap/login/admin", {"password": "wrong-password"}, 401),
            ("POST", server.http_url + "/v1/auth/login", {"username": "admin", "password": "wrong-password"}, 429),
            ("PUT", server.https_url + "/api/v1/auth/ldap/login/admin", {"password": "wrong-password"}, 429),
        ]
        for index, (method, url, payload, expected) in enumerate(attempts, 1):
            status, _ = server.client.json(method, url, data=payload)
            assert_status(expected, status, f"shared login throttle attempt {index}")


if __name__ == "__main__":
    main()

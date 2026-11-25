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
        status, token_page = server.client.request("GET", f"{server.https_url}/tokens.html")
        assert_status(200, status, "open canonical API tokens page")
        require(b'<dialog id="createTokenDialog"' in token_page, "token creation dialog")
        require(b'id="openCreateToken"' in token_page, "token page add button")
        require(
            b'id="copyToken"' in token_page
            and b'id="downloadClientCert"' in token_page
            and b'id="downloadClientKey"' in token_page,
            "token and certificate controls",
        )
        require(
            b"Sample vault-backup command" in token_page and b'id="copyCommand"' in token_page,
            "copyable wrapped sample command",
        )
        require(
            b"window.confirm" in token_page and b"addEventListener('beforeunload'" in token_page,
            "confirm dialog close and prevent accidental unload",
        )
        require(b">Cancel</button>" not in token_page, "remove cancel action")
        status, settings_page = server.client.request("GET", f"{server.https_url}/settings.html")
        assert_status(200, status, "open mTLS settings page")
        require(
            b'id="enforceMTLS"' in settings_page and b'id="autoRotate"' not in settings_page,
            "mTLS setting controls",
        )
        require(b'id="tokenLifetimeDays"' in token_page, "token expiry control")
        status, legacy_token_page = server.client.request("GET", f"{server.https_url}/token.html")
        assert_status(200, status, "redirect legacy API tokens URL")
        require(b"/tokens.html" in legacy_token_page, "legacy token URL canonical target")

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

        status, _ = server.client.json(
            "POST",
            f"{server.http_url}/v1/tokens",
            data={"name": "insecure-token"},
            headers=server.cookie_header(),
        )
        assert_status(426, status, "require HTTPS when issuing tokens and private keys")

        status, _ = server.client.json(
            "POST",
            f"{server.https_url}/v1/tokens",
            data={"name": "invalid-expiry", "expires_in_days": 366},
        )
        assert_status(400, status, "reject token lifetime above one year")
        status, _ = server.client.json(
            "POST",
            f"{server.https_url}/v1/tokens",
            data={"name": "invalid-expiry", "expires_in_days": 0},
        )
        assert_status(400, status, "reject non-positive token lifetime")

        api_token, token_id, token_data = server.create_api_token("backup-agent", expires_in_days=90)
        created = datetime.fromisoformat(token_data["created_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(token_data["expires_at"].replace("Z", "+00:00"))
        require(int((expires - created).total_seconds()) == 90 * 86400, "API token lifetime")
        print("PASS: create API token with selected lifetime")
        cert_expiry = datetime.fromisoformat(token_data["client_certificate_expires_at"].replace("Z", "+00:00"))
        require(cert_expiry == expires, "client certificate expires with API token")
        require("BEGIN CERTIFICATE" in token_data["client_certificate"], "client certificate returned on creation")
        require("BEGIN PRIVATE KEY" in token_data["client_private_key"], "client private key returned on creation")
        print("PASS: create token-linked client certificate with matching expiry")
        _, token_audit = server.client.json(
            "GET",
            f"{server.https_url}/v1/audit?action=create_token&q=api-token%3A{token_id}",
        )
        require(
            any(
                event["outcome"] == "success"
                and event["actor"] == server.user
                and event["resource"] == f"api-token:{token_id}"
                for event in token_audit["events"]
            ),
            "API token creation audit event",
        )
        require(api_token not in str(token_audit), "raw token leaked into creation audit")
        print("PASS: audit API token creation without storing raw token")

        duplicate_token, duplicate_token_id, default_token_data = server.create_api_token("backup-agent")
        require(duplicate_token_id != token_id, "duplicate-name API token IDs must be distinct")
        default_created = datetime.fromisoformat(default_token_data["created_at"].replace("Z", "+00:00"))
        default_expires = datetime.fromisoformat(default_token_data["expires_at"].replace("Z", "+00:00"))
        require(int((default_expires - default_created).total_seconds()) == 30 * 86400, "default API token lifetime")
        _, max_token_id, max_token_data = server.create_api_token("max-expiry-token", expires_in_days=365)
        max_created = datetime.fromisoformat(max_token_data["created_at"].replace("Z", "+00:00"))
        max_expires = datetime.fromisoformat(max_token_data["expires_at"].replace("Z", "+00:00"))
        require(int((max_expires - max_created).total_seconds()) == 365 * 86400, "one-year API token maximum")
        require(max_token_data["client_certificate_expires_at"] == max_token_data["expires_at"], "one-year certificate expiry")
        status, replacement = server.client.json(
            "POST",
            f"{server.https_url}/v1/tokens/{max_token_id}/certificate",
        )
        assert_status(201, status, "replace certificate for existing token")
        require(replacement["client_certificate_expires_at"] == max_token_data["expires_at"], "replacement certificate matches token expiry")
        _, tokens = server.client.json("GET", f"{server.https_url}/v1/tokens")
        require(
            sum(token["name"] == "backup-agent" for token in tokens) == 2,
            "multiple API tokens with the same name",
        )
        print("PASS: create multiple API tokens with the same name")

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

        _, settings = server.client.json("GET", f"{server.https_url}/v1/settings")
        require(settings == {"enforce_mtls": False}, "default mTLS settings")
        status, _ = server.client.json(
            "PUT",
            f"{server.https_url}/v1/settings",
            data={"enforce_mtls": True},
        )
        assert_status(200, status, "enable API mTLS")
        cert_client = server.client_with_certificate(
            token_data["client_certificate"], token_data["client_private_key"]
        )
        status, _ = server.client.request(
            "GET",
            f"{server.https_url}/api/v1/kv/data/token/test",
            headers=api_headers | {"X-Vault-Backup-Protocol": "client-cert-v1"},
        )
        assert_status(403, status, "require client certificate for Vault API")
        status, _ = cert_client.request(
            "GET",
            f"{server.https_url}/api/v1/kv/data/token/test",
            headers=api_headers,
        )
        assert_status(426, status, "reject clients without current CLI protocol")
        status, _ = cert_client.request(
            "GET",
            f"{server.https_url}/api/v1/kv/data/token/test",
            headers=api_headers | {"X-Vault-Backup-Protocol": "client-cert-v1"},
        )
        assert_status(200, status, "authorize matching managed token and client certificate")
        status, _ = cert_client.request(
            "GET",
            f"{server.https_url}/api/v1/kv/data/token/test",
            headers={"X-Vault-Token": duplicate_token, "X-Vault-Backup-Protocol": "client-cert-v1"},
        )
        assert_status(403, status, "reject a certificate paired with a different token")
        status, _ = server.client.request("GET", f"{server.https_url}/api/health")
        assert_status(200, status, "keep health checks available without mTLS")
        status, _ = server.client.request("GET", f"{server.https_url}/settings.html")
        assert_status(200, status, "keep admin settings page available without mTLS")
        status, _ = server.client.json(
            "PUT",
            f"{server.https_url}/v1/settings",
            data={"enforce_mtls": False},
        )
        assert_status(200, status, "disable API mTLS after certificate verification")

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
        _, revoke_audit = server.client.json(
            "GET",
            f"{server.https_url}/v1/audit?action=revoke_token&q=api-token%3A{token_id}",
        )
        require(
            any(
                event["outcome"] == "success"
                and event["actor"] == server.user
                and event["resource"] == f"api-token:{token_id}"
                for event in revoke_audit["events"]
            ),
            "API token revocation audit event",
        )
        print("PASS: audit API token revocation")
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

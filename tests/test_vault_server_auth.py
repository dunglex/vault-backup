#!/usr/bin/env python3
from datetime import datetime, timezone

from test_common import HttpClient, ServerTest, assert_status, require


def main() -> None:
    with ServerTest(18222, 18223) as server:
        status, _ = server.client.json(
            "POST",
            f"{server.https_url}/v1/setup/validate-key",
            data={"setup_key": "wrong"},
        )
        assert_status(401, status, "reject invalid setup key during key validation")
        status, _ = server.client.json(
            "POST",
            f"{server.https_url}/v1/setup/domains",
            data={
                "setup_key": "wrong",
                "main_domain": "vault.example.com",
                "alias_domains": [],
                "certificate_mode": "self_signed",
            },
        )
        assert_status(401, status, "reject invalid setup key during domain setup")
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
        status, account_page = server.client.request("GET", f"{server.https_url}/account.html")
        assert_status(200, status, "open account security page")
        require(
            b"Two-factor authentication" in account_page
            and b'<dialog id="totpSetupDialog"' in account_page
            and b'<dialog id="disableTOTPDialog"' in account_page
            and b'id="openDisableTOTPDialog"' in account_page
            and b"window.confirm('Disable two-factor authentication" not in account_page
            and b'id="setupPassword"' not in account_page
            and b'id="totpQRCode"' in account_page,
            "TOTP setup and disable dialogs",
        )
        require(b'id="logout"' in account_page, "keep Logout on the account page")
        status, qr_library = server.client.request("GET", f"{server.https_url}/qrcode.js")
        assert_status(200, status, "load local QR code library")
        require(b"QRCode.CorrectLevel" in qr_library, "serve QR code library")
        status, totp_settings = server.client.json("GET", f"{server.https_url}/v1/account/totp")
        assert_status(200, status, "read default TOTP settings")
        require(
            totp_settings["enabled"] is False and totp_settings["enforced"] is False,
            "TOTP enforcement is disabled by default",
        )
        status, token_page = server.client.request("GET", f"{server.https_url}/tokens.html")
        assert_status(200, status, "open canonical API tokens page")
        require(b"const enforceMTLS = false;" in token_page, "token page receives disabled mTLS setting")
        require(b'<dialog id="createTokenDialog"' in token_page, "token creation dialog")
        require(b'id="openCreateToken"' in token_page, "token page add button")
        require(
            b'id="copyToken"' in token_page
            and b'id="downloadClientCert"' not in token_page
            and b'id="downloadClientKey"' not in token_page
            and b"certificateButton.id = 'downloadClientCert'" in token_page
            and b"privateKeyButton.id = 'downloadClientKey'" in token_page,
            "render certificate download buttons only after credentials are issued",
        )
        require(
            b"actions.className = 'row-actions token-actions'" in token_page,
            "group certificate actions immediately before revoke",
        )
        require(
            b'id="credentialDownloads" class="row-actions" hidden' in token_page,
            "hide certificate downloads until credentials are issued",
        )
        status, admin_css = server.client.request("GET", f"{server.https_url}/admin.css")
        assert_status(200, status, "load admin styles")
        require(
            b"[hidden]" in admin_css and b"display: none !important;" in admin_css,
            "preserve hidden state when a component has display styling",
        )
        require(
            b"Sample vault-backup command" in token_page and b'id="sampleCommand"' in token_page,
            "wrapped sample command",
        )
        require(b'id="copyCommand"' not in token_page, "remove sample command copy button")
        require(
            b"window.confirm" in token_page and b"addEventListener('beforeunload'" in token_page,
            "confirm dialog close and prevent accidental unload",
        )
        require(b">Cancel</button>" not in token_page, "remove cancel action")
        status, security_page = server.client.request("GET", f"{server.https_url}/security.html")
        assert_status(200, status, "open mTLS security page")
        require(
            b'id="enforceMTLS"' in security_page
            and b'id="enforceMFA"' in security_page
            and b'id="autoBlockLoginBruteforceIP"' in security_page
            and b'id="viewBlockedIPs"' in security_page
            and b'id="blockedIPsDialog"' in security_page
            and b"Unblock" in security_page
            and b'id="autoRotate"' not in security_page,
            "security settings and blocked IP dialog",
        )
        require(b'id="logout"' not in security_page, "remove Logout from Security navigation")
        require(b'id="operatorForm"' not in security_page, "keep operator management out of Security")
        status, _ = server.client.request("GET", f"{server.https_url}/settings.html")
        assert_status(200, status, "open Security through the legacy Settings URL")
        status, operators_page = server.client.request("GET", f"{server.https_url}/operators.html")
        assert_status(200, status, "open operator management page")
        require(
            b'<dialog id="createOperatorDialog"' in operators_page
            and b'id="openCreateOperator"' in operators_page
            and b'id="operatorForm"' in operators_page
            and b'id="operatorPassword"' not in operators_page
            and b'id="acknowledgeOperatorPassword"' in operators_page
            and b"Reset password" in operators_page
            and b'id="logout"' not in operators_page,
            "popup operator creation form",
        )
        status, create_result = server.client.json(
            "POST",
            f"{server.https_url}/v1/operators",
            data={"username": "night-shift"},
        )
        assert_status(201, status, "create operator as admin")
        temporary_password = create_result.get("initial_password")
        require(
            isinstance(temporary_password, str) and 12 <= len(temporary_password) <= 20
            and create_result.get("must_change_password") is True,
            "return a one-time generated operator password",
        )
        status, operators = server.client.json("GET", f"{server.https_url}/v1/operators")
        assert_status(200, status, "list operators as admin")
        require(operators == {"operators": ["night-shift"]}, "operator listing")

        operator_client = HttpClient()
        status, _ = operator_client.json(
            "POST",
            f"{server.https_url}/v1/auth/login",
            data={"username": "night-shift", "password": temporary_password},
        )
        assert_status(200, status, "login as operator")
        status, operator_session = operator_client.json("GET", f"{server.https_url}/v1/session")
        assert_status(200, status, "read operator session")
        require(
            operator_session == {
                "authenticated": True,
                "role": "operator",
                "must_change_password": True,
            },
            "operator session requires a password change",
        )
        status, forced_password_page = operator_client.request("GET", f"{server.https_url}/secrets.html")
        assert_status(200, status, "redirect temporary-password session to account page")
        require(
            b'id="passwordChangeRequiredNotice"' in forced_password_page
            and b'<dialog id="passwordDialog"' in forced_password_page,
            "prompt for password change in a dialog",
        )
        status, _ = operator_client.json(
            "POST",
            f"{server.https_url}/v1/account/password",
            data={
                "current_password": temporary_password,
                "new_password": "operator-new-password",
                "repeat_new_password": "operator-new-password",
            },
        )
        assert_status(200, status, "change temporary operator password")
        status, operator_session = operator_client.json("GET", f"{server.https_url}/v1/session")
        assert_status(200, status, "read operator session after password change")
        require(operator_session["must_change_password"] is False, "clear first-login password requirement")
        status, reset_result = server.client.json(
            "POST",
            f"{server.https_url}/v1/operators/password",
            data={"username": "night-shift"},
        )
        assert_status(200, status, "reset operator password as admin")
        reset_password = reset_result.get("temporary_password")
        require(
            isinstance(reset_password, str) and 12 <= len(reset_password) <= 20
            and reset_result.get("must_change_password") is True,
            "return a one-time reset password",
        )
        status, _ = operator_client.request("GET", f"{server.https_url}/v1/session")
        assert_status(401, status, "revoke operator sessions after password reset")
        status, reset_login = operator_client.json(
            "POST",
            f"{server.https_url}/v1/auth/login",
            data={"username": "night-shift", "password": reset_password},
        )
        assert_status(200, status, "login with reset password")
        require(reset_login.get("must_change_password") is True, "require password change after admin reset")
        status, _ = operator_client.json(
            "POST",
            f"{server.https_url}/v1/account/password",
            data={
                "current_password": reset_password,
                "new_password": "operator-reset-password",
                "repeat_new_password": "operator-reset-password",
            },
        )
        assert_status(200, status, "change admin-reset temporary password")
        print("PASS: force a password change after an admin reset")
        status, _ = operator_client.request("GET", f"{server.https_url}/v1/settings")
        assert_status(403, status, "deny operator settings API access")
        status, _ = operator_client.json(
            "PUT",
            f"{server.https_url}/v1/settings",
            data={"enforce_mtls": True},
        )
        assert_status(403, status, "deny operator settings updates")
        status, _ = operator_client.request("GET", f"{server.https_url}/security.html")
        assert_status(403, status, "deny operator security page access")
        status, _ = operator_client.request("GET", f"{server.https_url}/settings.html")
        assert_status(403, status, "deny operator access through legacy Settings URL")
        status, _ = operator_client.request("GET", f"{server.https_url}/operators.html")
        assert_status(403, status, "deny operator management page access")
        status, operator_secrets = operator_client.request("GET", f"{server.https_url}/secrets.html")
        assert_status(200, status, "allow operator secrets page access")
        require(
            b'href="/security.html"' not in operator_secrets and b'href="/operators.html"' not in operator_secrets,
            "hide Admin navigation from operators",
        )
        status, _ = operator_client.request("GET", f"{server.https_url}/v1/tokens")
        assert_status(200, status, "allow operator token management")
        status, _ = operator_client.request("GET", f"{server.https_url}/v1/audit")
        assert_status(200, status, "allow operator audit access")
        status, operator_details = server.client.json(
            "GET",
            f"{server.https_url}/v1/operators/details",
        )
        assert_status(200, status, "read operator lock and MFA status")
        require(
            operator_details["operators"] == [{
                "username": "night-shift",
                "locked": False,
                "mfa_enabled": False,
                "mfa_configured": False,
            }],
            "operator status",
        )
        status, lock_result = server.client.json(
            "PATCH",
            f"{server.https_url}/v1/operators/lock",
            data={"username": "night-shift", "locked": True},
        )
        assert_status(200, status, "lock operator as admin")
        require(lock_result["locked"] is True, "operator lock status")
        status, _ = operator_client.request("GET", f"{server.https_url}/v1/session")
        assert_status(401, status, "revoke locked operator session")
        status, unlock_result = server.client.json(
            "PATCH",
            f"{server.https_url}/v1/operators/lock",
            data={"username": "night-shift", "locked": False},
        )
        assert_status(200, status, "unlock operator as admin")
        require(unlock_result["locked"] is False, "operator unlock status")
        status, _ = server.client.json(
            "DELETE",
            f"{server.https_url}/v1/operators",
            data={"username": "night-shift"},
        )
        assert_status(200, status, "remove operator as admin")
        status, _ = operator_client.request("GET", f"{server.https_url}/v1/session")
        assert_status(401, status, "revoke deleted operator web session")

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
        require(
            all(
                field not in token_data
                for field in ("client_certificate", "client_private_key", "client_certificate_expires_at")
            ),
            "token creation omits client credentials when mTLS is disabled",
        )
        status, _ = server.client.json(
            "POST",
            f"{server.https_url}/v1/tokens/{token_id}/certificate",
        )
        assert_status(409, status, "reject certificate issuance while mTLS is disabled")
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

        status, duplicate_name = server.client.json(
            "POST",
            f"{server.https_url}/v1/tokens",
            data={"name": "backup-agent"},
        )
        assert_status(409, status, "reject duplicate API token name")
        require("already exists" in duplicate_name["error"], "explain duplicate API token name")
        duplicate_token, duplicate_token_id, default_token_data = server.create_api_token("backup-agent-secondary")
        default_created = datetime.fromisoformat(default_token_data["created_at"].replace("Z", "+00:00"))
        default_expires = datetime.fromisoformat(default_token_data["expires_at"].replace("Z", "+00:00"))
        require(int((default_expires - default_created).total_seconds()) == 30 * 86400, "default API token lifetime")
        require("client_certificate" not in default_token_data, "default token has no certificate while mTLS is disabled")
        _, max_token_id, max_token_data = server.create_api_token("max-expiry-token", expires_in_days=365)
        max_created = datetime.fromisoformat(max_token_data["created_at"].replace("Z", "+00:00"))
        max_expires = datetime.fromisoformat(max_token_data["expires_at"].replace("Z", "+00:00"))
        require(int((max_expires - max_created).total_seconds()) == 365 * 86400, "one-year API token maximum")
        require("client_certificate" not in max_token_data, "max-lifetime token has no certificate while mTLS is disabled")
        _, tokens = server.client.json("GET", f"{server.https_url}/v1/tokens")
        require(
            sum(token["name"] == "backup-agent" for token in tokens) == 1,
            "keep one token per name",
        )
        print("PASS: reject duplicate API token names")

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
        require(
            settings
            == {
                "enforce_mtls": False,
                "auto_block_login_bruteforce_ip": False,
                "enforce_mfa": False,
                "file_logging": False,
                "automatic_server_backup": False,
                "server_backup_cron": "0 0 2 * * *",
                "server_backup_last_success": "",
            },
            "default security settings",
        )
        status, blocked = server.client.json(
            "GET", f"{server.https_url}/v1/settings/blocked-login-ips"
        )
        assert_status(200, status, "read blocked login IPs")
        require(blocked["blocked_ips"] == [], "blocked IP list is empty by default")
        status, _ = server.client.request(
            "DELETE",
            f"{server.https_url}/v1/settings/blocked-login-ips/198.51.100.250",
        )
        assert_status(404, status, "reject unblocking an IP that is not blocked")
        _, unblock_audit = server.client.json(
            "GET",
            f"{server.https_url}/v1/audit?action=unblock_login_ip&q=198.51.100.250",
        )
        require(
            any(event["outcome"] == "failure" for event in unblock_audit["events"]),
            "audit failed unblock request",
        )
        status, updated_settings = server.client.json(
            "PUT",
            f"{server.https_url}/v1/settings",
            data={"auto_block_login_bruteforce_ip": True},
        )
        assert_status(200, status, "enable automatic login IP blocking")
        require(
            updated_settings["auto_block_login_bruteforce_ip"] is True,
            "automatic login IP blocking is enabled",
        )
        status, updated_settings = server.client.json(
            "PUT",
            f"{server.https_url}/v1/settings",
            data={"enforce_mtls": False},
        )
        assert_status(200, status, "update mTLS without changing login IP blocking")
        require(
            updated_settings["auto_block_login_bruteforce_ip"] is True,
            "updating mTLS preserves login IP blocking setting",
        )
        status, updated_settings = server.client.json(
            "PUT",
            f"{server.https_url}/v1/settings",
            data={"auto_block_login_bruteforce_ip": False},
        )
        assert_status(200, status, "disable automatic login IP blocking")
        require(
            updated_settings["auto_block_login_bruteforce_ip"] is False,
            "automatic login IP blocking is disabled",
        )
        status, _ = server.client.json(
            "PUT",
            f"{server.https_url}/v1/settings",
            data={"enforce_mtls": True},
        )
        assert_status(200, status, "enable API mTLS")
        status, enabled_token_page = server.client.request("GET", f"{server.https_url}/tokens.html")
        assert_status(200, status, "open token page with mTLS enabled")
        require(b"const enforceMTLS = true;" in enabled_token_page, "token page receives enabled mTLS setting")
        status, issued = server.client.json(
            "POST",
            f"{server.https_url}/v1/tokens/{token_id}/certificate",
        )
        assert_status(201, status, "issue certificate for existing token when mTLS is enabled")
        require(issued["client_certificate_expires_at"] == token_data["expires_at"], "issued certificate matches token expiry")
        require("BEGIN CERTIFICATE" in issued["client_certificate"], "issued client certificate returned")
        require("BEGIN PRIVATE KEY" in issued["client_private_key"], "issued private key returned")
        token_data.update(issued)
        status, _ = server.client.json(
            "POST",
            f"{server.https_url}/v1/tokens/{max_token_id}/certificate",
        )
        assert_status(201, status, "issue certificate for max-lifetime token")
        status, replacement = server.client.json(
            "POST",
            f"{server.https_url}/v1/tokens/{max_token_id}/certificate",
        )
        assert_status(201, status, "replace certificate for existing token")
        require(replacement["client_certificate_expires_at"] == max_token_data["expires_at"], "replacement certificate matches token expiry")
        _, _, enabled_token_data = server.create_api_token("mtls-enabled-token")
        require(
            "client_certificate" in enabled_token_data
            and "client_private_key" in enabled_token_data
            and enabled_token_data["client_certificate_expires_at"] == enabled_token_data["expires_at"],
            "token creation issues matching client credentials when mTLS is enabled",
        )
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
        status, _ = server.client.request("GET", f"{server.https_url}/security.html")
        assert_status(200, status, "keep admin security page available without mTLS")
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
            ("POST", server.https_url + "/v1/auth/login", {"username": "admin", "password": "wrong-password"}, 429),
            ("PUT", server.https_url + "/api/v1/auth/ldap/login/admin", {"password": "wrong-password"}, 429),
            ("POST", server.http_url + "/v1/auth/login", {"username": "admin", "password": "wrong-password"}, 429),
            ("PUT", server.https_url + "/api/v1/auth/ldap/login/admin", {"password": "wrong-password"}, 429),
        ]
        for index, (method, url, payload, expected) in enumerate(attempts, 1):
            status, _ = server.client.json(method, url, data=payload)
            assert_status(expected, status, f"shared login throttle attempt {index}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import http.cookiejar
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


class TestFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TestFailure(message)


def assert_status(expected: int, actual: int, label: str) -> None:
    require(actual == expected, f"{label}: expected HTTP {expected}, got {actual}")
    print(f"PASS: {label}")


def run(*args: str | Path, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(arg) for arg in args],
        cwd=ROOT,
        env=env,
        check=check,
        text=True,
        capture_output=True,
    )


class HttpClient:
    def __init__(self, insecure: bool = True, client_cert: Path | None = None, client_key: Path | None = None):
        self.insecure = insecure
        self.cookies = http.cookiejar.CookieJar()
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        if client_cert and client_key:
            context.load_cert_chain(client_cert, client_key)
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(self.cookies),
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        data: dict | str | bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 10,
    ):
        request_headers = dict(headers or {})
        body: bytes | None
        if isinstance(data, dict):
            body = json.dumps(data).encode()
            request_headers.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            body = data.encode()
        else:
            body = data
        request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            return error.code, error.read()
        except urllib.error.URLError:
            return 0, b""
        with response:
            return response.status, response.read()

    def json(self, method: str, url: str, **kwargs):
        status, body = self.request(method, url, **kwargs)
        parsed = json.loads(body) if body else None
        return status, parsed


class ServerTest:
    def __init__(self, port: int, http_port: int, setup_key: str = "integration-test-setup-key"):
        self.port = port
        self.http_port = http_port
        self.setup_key = setup_key
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)
        self.cert = self.path / "test-cert.pem"
        self.key = self.path / "test-key.pem"
        self.server_binary = self.path / "vault-server"
        self.backup_binary = self.path / "vault-backup"
        self.process: subprocess.Popen[bytes] | None = None
        self.log_file = None
        self.https_url = f"https://127.0.0.1:{port}"
        self.http_url = f"http://127.0.0.1:{http_port}"
        self.management_url = self.https_url
        self.client = HttpClient()
        self.password = "integration-test-password"
        self.user = "admin"

    def __enter__(self):
        self.build()
        self.create_certificate()
        self.start()
        self.wait()
        return self

    def __exit__(self, *_):
        self.stop()
        if self.log_file:
            self.log_file.close()
        self.temp.cleanup()

    def build(self, backup: bool = False) -> None:
        server_env = os.environ | {"CGO_ENABLED": "1"}
        run(
            "go",
            "build",
            "-tags",
            "fts5 json1 secure_delete",
            "-o",
            self.server_binary,
            "./cmd/vault-server",
            env=server_env,
        )
        if backup:
            run("go", "build", "-o", self.backup_binary, "./cmd/vault-backup")

    def create_certificate(self) -> None:
        run(
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-keyout",
            self.key,
            "-out",
            self.cert,
        )

    def start(self) -> None:
        self.log_file = open(self.path / "server.log", "wb")
        env = os.environ | {
            "VAULT_SERVER_HTTPS_ADDR": f"127.0.0.1:{self.port}",
            "VAULT_SERVER_HTTP_ADDR": f"127.0.0.1:{self.http_port}",
            "VAULT_SERVER_DB": str(self.path / "vault.db"),
            "VAULT_SERVER_SECRETS_DB": str(self.path / "vault-secrets.db"),
            "VAULT_SERVER_DB_PASSWORD": self.password,
            "VAULT_SERVER_SETUP_KEY": self.setup_key,
        }
        self.process = subprocess.Popen(
            [str(self.server_binary), "--tls-cert", str(self.cert), "--tls-key", str(self.key)],
            cwd=ROOT,
            env=env,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
        )

    def wait(self) -> None:
        for _ in range(40):
            if self.process and self.process.poll() is not None:
                raise TestFailure((self.path / "server.log").read_text(errors="replace"))
            status, _ = self.client.request("GET", f"{self.https_url}/health", timeout=1)
            http_status, _ = self.client.request("GET", f"{self.http_url}/health", timeout=1)
            if status == 200 and http_status == 200:
                return
            time.sleep(0.25)
        raise TestFailure("server did not become healthy")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=20)
        self.process = None

    def setup(self) -> None:
        status, body = self.client.json(
            "POST",
            f"{self.management_url}/v1/setup/validate-key",
            data={"setup_key": self.setup_key},
        )
        assert_status(200, status, "validate setup key")
        require(body == {"valid": True}, "setup-key validation response")

        status, body = self.client.json(
            "POST",
            f"{self.management_url}/v1/setup/domains",
            data={
                "setup_key": self.setup_key,
                "main_domain": "127.0.0.1",
                "alias_domains": ["localhost"],
                "certificate_mode": "self_signed",
            },
        )
        assert_status(200, status, "configure server domains")
        require(body == {"saved": True}, "domain setup response")

        status, body = self.client.json(
            "POST",
            f"{self.management_url}/v1/setup",
            data={
                "setup_key": self.setup_key,
                "username": self.user,
                "password": self.password,
                "password_confirmation": self.password,
            },
        )
        assert_status(201, status, "set up vault server")
        require(
            body == {
                "username": self.user,
                "redirect_url": "https://127.0.0.1/login.html",
            },
            "setup response",
        )

    def login(self):
        status, body = self.client.json(
            "POST",
            f"{self.management_url}/v1/auth/login",
            data={"username": self.user, "password": self.password},
        )
        assert_status(200, status, "login")
        return body["token"]

    def create_api_token(
        self, name: str = "test-token", expires_in_days: int | None = None
    ) -> tuple[str, int, dict]:
        data: dict[str, str | int | list[str]] = {
            "name": name,
            "prefixes": ["kv/app", "kv/token", "kv/session"],
        }
        if expires_in_days is not None:
            data["expires_in_days"] = expires_in_days
        status, body = self.client.json(
            "POST",
            f"{self.management_url}/v1/tokens",
            data=data,
        )
        assert_status(201, status, f"create managed API token {name}")
        return body["token"], body["id"], body

    def cookie_header(self) -> dict[str, str]:
        values = [
            f"{cookie.name}={cookie.value}"
            for cookie in self.client.cookies
            if cookie.name == "vault_session"
        ]
        return {"Cookie": "; ".join(values)} if values else {}

    def client_with_certificate(self, certificate: str, private_key: str) -> HttpClient:
        cert_path = self.path / "managed-client-cert.pem"
        key_path = self.path / "managed-client-key.pem"
        cert_path.write_text(certificate)
        key_path.write_text(private_key)
        cert_path.chmod(0o600)
        key_path.chmod(0o600)
        return HttpClient(client_cert=cert_path, client_key=key_path)


class BackupServerTest(ServerTest):
    def __init__(self, port: int = 18210, http_port: int = 18211):
        super().__init__(port, http_port, "backup-test-setup-key")
        self.password = "backup-test-password"
        self.http_url = f"http://127.0.0.1:{http_port}"
        self.https_url = f"http://127.0.0.1:{http_port}"
        self.management_url = f"https://127.0.0.1:{port}"

    def __enter__(self):
        self.build(backup=True)
        self.create_certificate()
        self.start()
        self.wait()
        self.setup()
        self.login()
        self.api_token, self.api_token_id, _ = self.create_api_token("backup-test")
        return self

    def start(self) -> None:
        super().start()
        self.https_url = f"http://127.0.0.1:{self.http_port}"

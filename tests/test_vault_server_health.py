#!/usr/bin/env python3
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from test_common import ROOT, ServerTest, assert_status, require


def main() -> None:
    with ServerTest(18220, 18221) as server:
        for path, label in [("/health", "health endpoint"), ("/api/health", "API health endpoint")]:
            status, body = server.client.request("GET", server.https_url + path)
            assert_status(200, status, label)
            require(json.loads(body) == {"ok": True}, label + " response")
        status, body = server.client.request("GET", server.http_url + "/health")
        assert_status(200, status, "HTTP health endpoint")
        require(json.loads(body) == {"ok": True}, "HTTP health response")

        status, body = server.client.request("GET", server.https_url + "/")
        assert_status(200, status, "serve embedded web page")
        require(b"Vault Server" in body, "embedded page content")
        print("PASS: embedded page content")

        server.process.send_signal(signal.SIGTERM)
        require(server.process.wait(timeout=20) == 0, "graceful shutdown exit code")
        server.process = None
        status, _ = server.client.request("GET", server.https_url + "/health", timeout=1)
        require(status == 0, "HTTPS listener remained available after shutdown")
        require("Vault server shut down" in (server.path / "server.log").read_text(), "shutdown log")

        with open(server.path / "reopen.log", "wb") as log:
            env = os.environ | {
                "VAULT_SERVER_DB_PASSWORD": server.password,
            }
            process = subprocess.Popen(
                [
                    str(server.server_binary),
                    "--https-addr",
                    "127.0.0.1:0",
                    "--db",
                    str(server.path / "vault.db"),
                    "--tls-cert",
                    str(server.cert),
                    "--tls-key",
                    str(server.key),
                ],
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                for _ in range(50):
                    text = (server.path / "reopen.log").read_text()
                    if "Vault server serving HTTPS" in text:
                        break
                    require(process.poll() is None, text)
                    time.sleep(0.2)
                else:
                    raise AssertionError("reopened server did not start")
            finally:
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=20)
        print("PASS: graceful shutdown closes listeners and database")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import tempfile
import threading

from test_common import require, run


class QuietHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class NoRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.end_headers()

    def log_message(self, _format, *_args):
        pass


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        temp = Path(temporary_directory)
        server_cert = temp / "server-ca.pem"
        server_key = temp / "server-key.pem"
        invalid_cert = temp / "untrusted-client.pem"
        invalid_key = temp / "untrusted-client-key.pem"
        backup_binary = temp / "vault-backup"

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
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
            server_key,
            "-out",
            server_cert,
        )
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
            "/CN=untrusted-client",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
            invalid_key,
            "-out",
            invalid_cert,
        )
        run("go", "build", "-o", backup_binary, "./cmd/vault-backup")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(server_cert, server_key)
        context.load_verify_locations(cafile=server_cert)
        context.verify_mode = ssl.CERT_REQUIRED
        server = QuietHTTPServer(("127.0.0.1", 0), NoRequestHandler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            url = f"https://127.0.0.1:{server.server_address[1]}/api"
            for name, client_cert_args in (
                ("missing client certificate", ()),
                (
                    "untrusted client certificate",
                    ("--client_cert", invalid_cert, "--client_key", invalid_key),
                ),
            ):
                result = run(
                    backup_binary,
                    "--url",
                    url,
                    "--ca_cert",
                    server_cert,
                    "--token",
                    "test-token",
                    "--secret_name",
                    "kv",
                    "--secret_path",
                    "app/database",
                    "--output_mode",
                    "data",
                    *client_cert_args,
                    check=False,
                )
                require(result.returncode == 1, f"{name}: expected exit 1, got {result.returncode}: {result.stderr}")
                require(
                    "Vault rejected the client certificate during the TLS handshake" in result.stderr,
                    f"{name}: clean handshake error missing: {result.stderr}",
                )
                require("remote error: tls:" not in result.stderr, f"{name}: raw TLS alert leaked: {result.stderr}")
                print(f"PASS: clean vault-backup error for {name}")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()

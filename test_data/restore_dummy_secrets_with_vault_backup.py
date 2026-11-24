#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Restore JSON dummy secrets using the vault-backup CLI."
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("VAULT_URL", "https://127.0.0.1:8200/api"),
        help="Vault API URL (default: VAULT_URL or https://127.0.0.1:8200/api)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("VAULT_TOKEN", ""),
        help="managed API token (default: VAULT_TOKEN)",
    )
    parser.add_argument(
        "--mount",
        default=os.environ.get("VAULT_SECRET_NAME", "kv"),
        help="Vault KV mount (default: VAULT_SECRET_NAME or kv)",
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=ROOT / "test_data",
        help="directory of JSON files to restore (default: ./test_data)",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=ROOT / "bin" / "vault-backup",
        help="vault-backup executable (default: ./bin/vault-backup)",
    )
    parser.add_argument("--insecure-tls", action="store_true", help="skip TLS verification")
    parser.add_argument("--ca-cert", help="CA certificate PEM")
    parser.add_argument("--client-cert", help="mTLS client certificate PEM")
    parser.add_argument("--client-key", help="mTLS client private key PEM")
    parser.add_argument("--tls-server-name", help="TLS server name override")
    args = parser.parse_args()

    input_dir = args.input_dir.expanduser().resolve()
    binary = args.binary.expanduser().resolve()
    if not args.token:
        parser.error("a managed API token is required via --token or VAULT_TOKEN")
    if not args.mount or "/" in args.mount:
        parser.error("mount must be a non-empty path segment")
    if not input_dir.is_dir():
        parser.error(f"input directory does not exist: {input_dir}")
    if not binary.is_file():
        parser.error(f"vault-backup executable not found: {binary}")

    files = sorted(input_dir.rglob("*.json"))
    if not files:
        parser.error(f"no JSON secret files found in {input_dir}")

    child_env = os.environ.copy()
    child_env["VAULT_TOKEN"] = args.token
    for file_path in files:
        secret_path = file_path.relative_to(input_dir).with_suffix("").as_posix()
        command = [
            str(binary),
            "--url",
            args.url,
            "--secret_name",
            args.mount,
            "--secret_path",
            secret_path,
            "--restore",
            "--input_path",
            str(file_path),
        ]
        if args.insecure_tls:
            command.append("--insecure")
        if args.ca_cert:
            command.extend(["--ca_cert", args.ca_cert])
        if args.client_cert:
            command.extend(["--client_cert", args.client_cert])
        if args.client_key:
            command.extend(["--client_key", args.client_key])
        if args.tls_server_name:
            command.extend(["--tls_server_name", args.tls_server_name])
        subprocess.run(command, cwd=ROOT, env=child_env, check=True)

    print(f"PASS: restored {len(files)} JSON secret files")


if __name__ == "__main__":
    main()

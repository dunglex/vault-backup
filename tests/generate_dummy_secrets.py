#!/usr/bin/env python3
import argparse
import os

from test_common import HttpClient, require


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deterministic dummy secrets on a running Vault-compatible server.")
    parser.add_argument("--url", default=os.environ.get("VAULT_URL", "https://127.0.0.1:8200/api"))
    parser.add_argument("--token", default=os.environ.get("VAULT_TOKEN", ""))
    parser.add_argument("--mount", default=os.environ.get("VAULT_SECRET_NAME", "kv"))
    parser.add_argument("--prefix", default="dummy/load-test")
    parser.add_argument("--count", type=positive_int, default=100)
    parser.add_argument("--insecure-tls", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()

    if not args.token:
        parser.error("a managed API token is required via --token or VAULT_TOKEN")
    if not args.mount or "/" in args.mount:
        parser.error("mount must be a non-empty path segment")
    prefix = args.prefix.strip("/")
    if not prefix or "\n" in prefix or ".." in prefix:
        parser.error("prefix must be a non-empty safe relative path")

    base_url = args.url.rstrip("/")
    client = HttpClient(insecure=args.insecure_tls)
    status, _ = client.request("GET", base_url + "/health")
    require(status == 200, f"server health check returned HTTP {status}")
    headers = {"X-Vault-Token": args.token}

    print(f"Generating {args.count} dummy secrets under {args.mount}/{prefix} ...")
    for number in range(1, args.count + 1):
        identifier = f"{number:06d}"
        path = f"{prefix}/{identifier}"
        marker = f"dummy-secret-{identifier}"
        status, _ = client.request(
            "PUT",
            f"{base_url}/v1/{args.mount}/data/{path}",
            data={
                "data": {
                    "name": identifier,
                    "sequence": number,
                    "kind": "load-test",
                    "value": marker,
                }
            },
            headers=headers,
        )
        require(status == 200, f"failed to create {path}: HTTP {status}")
        status, body = client.request(
            "GET", f"{base_url}/v1/{args.mount}/data/{path}", headers=headers
        )
        require(status == 200 and marker.encode() in body, f"verification failed for {path}")
        if number == 1 or number % 100 == 0 or number == args.count:
            print(f"Created and verified {number}/{args.count}")

    print(f"PASS: generated and verified {args.count} dummy secrets")
    if args.cleanup:
        for number in range(1, args.count + 1):
            path = f"{prefix}/{number:06d}"
            status, _ = client.request(
                "DELETE", f"{base_url}/v1/{args.mount}/data/{path}", headers=headers
            )
            require(status == 204, f"failed to delete {path}: HTTP {status}")
        print(f"PASS: deleted {args.count} generated dummy secrets")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PREFIXES = (
    "apps/production",
    "apps/staging",
    "databases/postgres",
    "databases/redis",
    "infrastructure/kubernetes",
    "monitoring/alerts",
    "services/payments",
    "teams/platform",
)
SECRET_KINDS = (
    "application",
    "database",
    "infrastructure",
    "monitoring",
    "service",
)
SEGMENT_PATTERN = re.compile(r"[A-Za-z0-9-]{1,127}\Z")


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def parse_prefix(value: str) -> str:
    prefix = value.strip("/")
    if not prefix or any(not SEGMENT_PATTERN.fullmatch(part) for part in prefix.split("/")):
        raise argparse.ArgumentTypeError(
            "prefix must contain slash-separated segments of 1-127 letters, numbers, or hyphens"
        )
    return prefix


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate local JSON files containing dummy Vault secrets."
    )
    parser.add_argument(
        "--count",
        type=positive_int,
        default=100,
        help="number of secrets to generate under each prefix (default: 100)",
    )
    parser.add_argument(
        "--prefix",
        action="append",
        type=parse_prefix,
        help="secret path prefix; repeat to generate multiple groups (defaults to built-in prefixes)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "test_data",
        help="output directory (default: ./test_data)",
    )
    args = parser.parse_args()

    prefixes = args.prefix or list(DEFAULT_PREFIXES)
    if len(set(prefixes)) != len(prefixes):
        parser.error("prefixes must be unique")

    total = args.count * len(prefixes)
    print(f"Generating {total} JSON dummy secrets in {args.output_dir} ...")
    generated = 0
    for prefix_index, prefix in enumerate(prefixes):
        for sequence in range(1, args.count + 1):
            identifier = f"{sequence:06d}"
            path = args.output_dir.joinpath(*prefix.split("/"), f"{identifier}.json")
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "enabled": sequence % 2 == 0,
                "kind": SECRET_KINDS[(sequence + prefix_index) % len(SECRET_KINDS)],
                "name": f"{prefix.split('/')[-1]}-{identifier}",
                "prefix": prefix,
                "sequence": sequence,
                "value": f"dummy-secret-{prefix.replace('/', '-')}-{identifier}",
            }
            path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            path.chmod(0o600)
            generated += 1
            if generated == 1 or generated % 100 == 0 or generated == total:
                print(f"Generated {generated}/{total}")

    print(f"PASS: generated {generated} JSON dummy secrets")


if __name__ == "__main__":
    main()

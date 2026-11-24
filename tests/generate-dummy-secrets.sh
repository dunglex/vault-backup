#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: generate-dummy-secrets.sh [options]

Generate deterministic dummy secrets on a running Vault-compatible server.

Options:
  --url URL          Vault API base URL (default: VAULT_URL or https://127.0.0.1:8200/api)
  --token TOKEN      Admin-created managed API token (default: VAULT_TOKEN)
  --mount NAME       KV mount (default: VAULT_SECRET_NAME or kv)
  --prefix PATH      Secret namespace (default: dummy/load-test)
  --count NUMBER     Number of secrets (default: 100)
  --insecure-tls     Disable TLS certificate verification
  --cleanup          Delete generated secrets after verification
  -h, --help         Show this help
EOF
}

URL=${VAULT_URL:-https://127.0.0.1:8200/api}
TOKEN=${VAULT_TOKEN:-}
MOUNT=${VAULT_SECRET_NAME:-kv}
PREFIX=dummy/load-test
COUNT=100
INSECURE_TLS=false
CLEANUP=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      URL=$2
      shift 2
      ;;
    --token)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      TOKEN=$2
      shift 2
      ;;
    --mount)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      MOUNT=$2
      shift 2
      ;;
    --prefix)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      PREFIX=$2
      shift 2
      ;;
    --count)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      COUNT=$2
      shift 2
      ;;
    --insecure-tls)
      INSECURE_TLS=true
      shift
      ;;
    --cleanup)
      CLEANUP=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$COUNT" =~ ^[1-9][0-9]*$ ]]; then
  echo "count must be a positive integer" >&2
  exit 2
fi
if [[ -z "$TOKEN" ]]; then
  echo "A managed API token is required via --token or VAULT_TOKEN" >&2
  exit 2
fi
if [[ -z "$MOUNT" || "$MOUNT" == */* ]]; then
  echo "mount must be a non-empty path segment" >&2
  exit 2
fi
PREFIX=${PREFIX#/}
PREFIX=${PREFIX%/}
if [[ -z "$PREFIX" || "$PREFIX" == *$'\n'* || "$PREFIX" == *'..'* ]]; then
  echo "prefix must be a non-empty safe relative path" >&2
  exit 2
fi

URL=${URL%/}
CURL_TLS=()
if [[ "$INSECURE_TLS" == true ]]; then
  CURL_TLS+=(--insecure)
fi

curl "${CURL_TLS[@]}" --fail --silent --show-error --max-time 10 \
  "$URL/health" >/dev/null

printf 'Generating %d dummy secrets under %s/%s ...\n' "$COUNT" "$MOUNT" "$PREFIX"
for ((i = 1; i <= COUNT; i++)); do
  id=$(printf '%06d' "$i")
  path="$PREFIX/$id"
  marker="dummy-secret-$id"
  payload=$(printf '{"data":{"name":"%s","sequence":%d,"kind":"load-test","value":"%s"}}' "$id" "$i" "$marker")

  curl "${CURL_TLS[@]}" --fail --silent --show-error \
    -H "X-Vault-Token: $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$payload" \
    -X PUT "$URL/v1/$MOUNT/data/$path" >/dev/null

  response=$(curl "${CURL_TLS[@]}" --fail --silent --show-error \
    -H "X-Vault-Token: $TOKEN" \
    "$URL/v1/$MOUNT/data/$path")
  if [[ "$response" != *"$marker"* ]]; then
    echo "Verification failed for $path" >&2
    exit 1
  fi

  if ((i == 1 || i % 100 == 0 || i == COUNT)); then
    printf 'Created and verified %d/%d\n' "$i" "$COUNT"
  fi
done

echo "PASS: generated and verified $COUNT dummy secrets"

if [[ "$CLEANUP" == true ]]; then
  for ((i = 1; i <= COUNT; i++)); do
    id=$(printf '%06d' "$i")
    curl "${CURL_TLS[@]}" --fail --silent --show-error \
      -H "X-Vault-Token: $TOKEN" \
      -X DELETE "$URL/v1/$MOUNT/data/$PREFIX/$id" >/dev/null
  done
  echo "PASS: deleted $COUNT generated dummy secrets"
fi

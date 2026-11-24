#!/usr/bin/env bash

set -xeuo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

cd "$ROOT_DIR"

# to user docker
# set BUILDER=docker (cmd)
# or export BUILDER=docker (bash)
BUILDER=${BUILDER:-podman}

# Set the format flag for podman
# https://docs.podman.io/en/stable/markdown/podman-push.1.html
FORMAT_FLAG=""
if [ "$BUILDER" = "podman" ]; then
  FORMAT_FLAG="--format=v2s2"
fi

# NOPUSH flag
# if set to true, images will not be pushed to the registry
NOPUSH=${NOPUSH:-false}

# Set the registry
REGISTRY="registry.vn.eit.zone"

TARGET="$REGISTRY/hr-digi/vault-server:latest"

$BUILDER build --progress=plain --platform linux/amd64 --tag "$TARGET" .

if [ "$NOPUSH" = false ]; then
  $BUILDER login "$REGISTRY"
  $BUILDER push $FORMAT_FLAG "$TARGET"
fi
#!/usr/bin/env bash

set -xeu

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

APPS=(vault-backup vault-server)

for APP in "${APPS[@]}"; do
  IMAGE="hr-digi/$APP"
  TARGET="$REGISTRY/$IMAGE:latest"

  $BUILDER build \
    --progress=plain \
    --platform linux/amd64 \
    --build-arg "APP=$APP" \
    --tag "$TARGET" \
    .

  if [ "$NOPUSH" = false ]; then
    if [ "$APP" = "${APPS[0]}" ]; then
      $BUILDER login "$REGISTRY"
    fi
    $BUILDER push $FORMAT_FLAG "$TARGET"
  fi
done
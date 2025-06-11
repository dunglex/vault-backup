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

IMAGE="hr-digi/vault-backup"
$BUILDER build --progress=plain --platform linux/amd64 --tag $REGISTRY/$IMAGE:latest .

# Push images if NOPUSH is not set
if [ "$NOPUSH" = false ]; then
  $BUILDER login $REGISTRY
  $BUILDER push $FORMAT_FLAG $REGISTRY/$IMAGE
fi
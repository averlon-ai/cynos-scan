#!/usr/bin/env bash
# Refuse to publish over a version tag. Buildx's explicit missing-manifest response is the
# only permitted failure: authentication, network and registry errors must stop the release.
set -euo pipefail

reference="${1:?usage: assert-image-tag-absent.sh IMAGE:TAG}"
if output="$(docker buildx imagetools inspect "$reference" 2>&1)"; then
  echo "::error::$reference already exists; bump the packages' version" >&2
  exit 1
fi

case "$output" in
  "$reference: not found" | "ERROR: $reference: not found") ;;
  *)
    echo "::error::Could not establish that $reference is absent; refusing to publish" >&2
    printf '%s\n' "$output" >&2
    exit 1
    ;;
esac

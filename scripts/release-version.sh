#!/usr/bin/env bash
# Normalize and validate the exact semantic-version tags emitted by release.yml
# and consumed by the bundled GitHub Action. Build metadata is intentionally
# rejected because release assets are published under one immutable tag.
set -euo pipefail

tag="${1:-}"
if [[ -z "$tag" ]]; then
  echo "usage: release-version.sh TAG" >&2
  exit 2
fi

if [[ "$tag" != v* ]]; then
  tag="v$tag"
fi

if ! [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
  echo "invalid release tag; expected vMAJOR.MINOR.PATCH with an optional prerelease suffix" >&2
  exit 2
fi

printf '%s\n' "$tag"

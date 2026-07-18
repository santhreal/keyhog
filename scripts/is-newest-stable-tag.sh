#!/usr/bin/env bash
# Single owner for the "is this the newest stable release" predicate used by
# release.yml to decide whether a release should advance the floating pointers
# (the `latest` container image and the `v<major>` action tag). A prerelease
# (any `-suffix`) is never newest-stable. Otherwise the tag is newest only when
# it sorts last among all `vMAJOR.MINOR.PATCH` tags. Prints `true` or `false`.
#
# Two release jobs consumed a byte-identical copy of this logic; a drift between
# them would move one floating pointer but not the other. Keep it here, once.
set -euo pipefail

tag="${1:-}"
if [[ -z "$tag" ]]; then
  echo "usage: is-newest-stable-tag.sh TAG" >&2
  exit 2
fi

if [[ "$tag" == *-* ]]; then
  printf 'false\n'
  exit 0
fi

git fetch --force --tags origin >&2
newest="$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' \
  | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
  | sort -V | tail -n 1)"

if [[ "$tag" == "$newest" ]]; then
  printf 'true\n'
else
  printf 'false\n'
fi

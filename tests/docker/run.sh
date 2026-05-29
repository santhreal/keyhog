#!/usr/bin/env bash
#
# Build the keyhog integration images and run the scenario battery against
# each. The (image x scenario) product is the integration matrix; this is the
# entry point CI and local dogfooding call.
#
#   tests/docker/run.sh [glibc|musl|all]   (default: all)
#
# Exits non-zero if any image build or any scenario fails.

set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2  # repo root
which="${1:-all}"
rc=0

build_and_run() {
  local variant="$1" dockerfile="$2"
  local tag="keyhog-test:$variant"
  echo "### building $tag ($dockerfile)"
  if ! docker build -f "$dockerfile" -t "$tag" .; then
    echo "✗ image build failed: $tag"
    return 1
  fi
  bash tests/docker/scenarios.sh "$tag"
}

case "$which" in
  glibc) build_and_run glibc tests/docker/Dockerfile.glibc || rc=1 ;;
  musl) build_and_run musl tests/docker/Dockerfile.musl || rc=1 ;;
  all)
    build_and_run glibc tests/docker/Dockerfile.glibc || rc=1
    build_and_run musl tests/docker/Dockerfile.musl || rc=1
    ;;
  *)
    echo "usage: run.sh [glibc|musl|all]" >&2
    exit 2
    ;;
esac

if [[ "$rc" == 0 ]]; then
  echo "ALL DOCKER INTEGRATION MATRICES PASSED"
else
  echo "DOCKER INTEGRATION FAILURES - see above"
fi
exit $rc

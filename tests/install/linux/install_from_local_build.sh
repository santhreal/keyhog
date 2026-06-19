#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
exec bash "$ROOT/tests/install/fixtures/install_from_local_build_posix.sh" "$@"

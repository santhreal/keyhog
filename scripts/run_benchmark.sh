#!/usr/bin/env bash
# Compatibility entrypoint for the canonical benchmark harness.
#
# Environment overrides:
#   CORPUS=mirror
#   SCANNERS=keyhog,trufflehog
#   GATE_SCANNERS=keyhog,trufflehog
#   REQUIRE_COMPETITORS=trufflehog
#   OUT=results
#   MAKE=make

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BENCH_DIR="$ROOT_DIR/benchmarks"

CORPUS="${CORPUS:-mirror}"
SCANNERS="${SCANNERS:-keyhog,trufflehog}"
GATE_SCANNERS="${GATE_SCANNERS:-$SCANNERS}"
REQUIRE_COMPETITORS="${REQUIRE_COMPETITORS:-trufflehog}"
OUT="${OUT:-results}"
MAKE_BIN="${MAKE:-make}"

if ! command -v "$MAKE_BIN" >/dev/null; then
    echo "error: make not found; install make or set MAKE=/path/to/make." >&2
    exit 2
fi

if [[ "$CORPUS" == "mirror" ]]; then
    "$MAKE_BIN" -C "$BENCH_DIR" mirror
fi

"$MAKE_BIN" -C "$BENCH_DIR" leaderboard \
    CORPUS="$CORPUS" \
    SCANNERS="$SCANNERS" \
    OUT="$OUT"

"$MAKE_BIN" -C "$BENCH_DIR" gate \
    CORPUS="$CORPUS" \
    GATE_SCANNERS="$GATE_SCANNERS" \
    REQUIRE_COMPETITORS="$REQUIRE_COMPETITORS" \
    OUT="$OUT"

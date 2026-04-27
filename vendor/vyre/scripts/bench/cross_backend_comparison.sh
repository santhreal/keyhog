#!/usr/bin/env bash
#
# CI wrapper for `xtask bench-crossback`. Runs the cross-backend
# comparison for every known program, writes one markdown file
# per program under `docs/perf/`. Part of C-B12.
#
# Modes:
#   default              CPU-reference-only timing.
#   VYRE_BENCH_GPU=1     Enables wgpu timing column (requires real GPU).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

mkdir -p docs/perf

PROGRAMS=(xor-1k xor-1m)
for program in "${PROGRAMS[@]}"; do
  echo "=== $program ==="
  cargo run --quiet -p xtask -- bench-crossback "$program"
done

echo ""
echo "cross-backend tables written under docs/perf/."

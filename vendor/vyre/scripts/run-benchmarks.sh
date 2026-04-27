#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo bench --bench primitives_showcase -- --sample-size 10

test -s benches/RESULTS.md
test -s benches/RESULTS.json

git add \
  Cargo.toml \
  README.md \
  vyre-core/docs/SUMMARY.md \
  vyre-core/docs/benchmarks.md \
  benches/RESULTS.md \
  benches/RESULTS.json \
  benches/primitives_showcase.rs \
  benches/primitives_showcase_support \
  scripts/run-benchmarks.sh

if git diff --cached --quiet; then
  echo "No benchmark artifact changes to commit."
else
  git commit -m "Add primitive benchmark showcase results"
fi

#!/usr/bin/env bash
# Per-crate coverage gate. Runs `cargo llvm-cov` for the crates we track,
# writes JSON reports, prints a summary, and optionally enforces thresholds
# read from `coverage_thresholds.json` in the repo root.
#
# Usage:
#   scripts/gates/coverage.sh              # run, print summary, pass
#   scripts/gates/coverage.sh --enforce    # fail if any crate is below threshold
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

ENFORCE=0
if [ "${1:-}" = "--enforce" ]; then
  ENFORCE=1
fi

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/mnt/FlareTraining/santh-archive/cargo-target}"
export CARGO_TARGET_DIR

FEATURES="github,gitlab,bitbucket,slack,azure,gcs,s3,docker,binary"
REPORT_DIR="${CARGO_TARGET_DIR}/coverage-reports"
mkdir -p "$REPORT_DIR"

run_report() {
  local crate="$1"
  local extra_args="${2:-}"
  echo "==> ${crate} coverage"
  # shellcheck disable=SC2086
  cargo llvm-cov -p "$crate" $extra_args --json \
    --output-path "${REPORT_DIR}/${crate}.json" || exit 1
}

run_report keyhog-sources "--lib --test all_tests --features ${FEATURES}"
run_report keyhog-core    "--lib"
run_report keyhog-scanner "--lib"

python3 - "$REPORT_DIR" "$ENFORCE" <<'PY'
import json, pathlib, sys

report_dir = pathlib.Path(sys.argv[1])
enforce = int(sys.argv[2])

threshold_path = pathlib.Path("coverage_thresholds.json")
thresholds = {}
if threshold_path.exists():
    thresholds = json.loads(threshold_path.read_text())

def summarize(path):
    data = json.loads(path.read_text())
    files = data['data'][0]['files']
    covered = 0
    total = 0
    for f in files:
        counts = {}
        for seg in f['segments']:
            line, col, count, has_count, is_region_entry, is_gap = seg
            if has_count and not is_gap:
                counts[line] = max(counts.get(line, 0), count)
        covered += sum(1 for v in counts.values() if v > 0)
        total += len(counts)
    return covered, total

rc = 0
print("\n=== coverage summary ===")
for report in sorted(report_dir.glob("*.json")):
    crate = report.stem
    covered, total = summarize(report)
    pct = covered / total * 100 if total else 0.0
    threshold = thresholds.get(crate, 0.0)
    status = "OK" if pct >= threshold else "BELOW"
    print(f"{crate}: {covered}/{total} ({pct:.2f}%) threshold={threshold:.2f}% [{status}]")
    if enforce and pct < threshold:
        rc = 1

sys.exit(rc)
PY

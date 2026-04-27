#!/usr/bin/env bash
# Phase 23a enforcement: every .expect("...") / .unwrap_or_else(...) must
# include an actionable "Fix:" clause documenting how the caller recovers.
#
# Ratchet mode: set VYRE_EXPECT_BASELINE to the committed baseline count; the
# script fails if the current count exceeds the baseline, allowing a
# monotonic reduction without forcing a single giant cleanup commit.
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

count=$(grep -rn '\.expect("' --include='*.rs' \
  --exclude-dir=target --exclude-dir=.git \
  . 2>/dev/null \
  | grep -v 'Fix:' \
  | grep -v '/tests/' \
  | grep -v '/benches/' \
  | wc -l \
  | tr -d ' ')

baseline="${VYRE_EXPECT_BASELINE:-0}"

echo "expect() sites lacking 'Fix:' guidance: $count (baseline $baseline)"

if (( count > baseline )); then
  echo "New expect() site without 'Fix:' annotation — ratchet violated." >&2
  echo "Either add a Fix: clause or bump the baseline in scripts/check_expect_has_fix.sh." >&2
  exit 1
fi

exit 0

#!/usr/bin/env bash
#
# Layout Law — file-size cap.
#
# Every .rs file under a vyre-* crate's src/ must be ≤ 500 lines.
# Above that size a file is doing more than one thing; split into
# one-responsibility modules per the Unix-philosophy contract.
#
# Modes:
#   default  — warn on violations, exit 0 (informational)
#   strict   — fail on any violation (set VYRE_LAW_STRICT=1)
#
# The gate flips from informational → strict once the tree fully
# settles after the dialect migration (A-C11c in the Claude plan).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

MAX_LINES=500
STRICT="${VYRE_LAW_STRICT:-0}"

violations=()
while IFS= read -r -d '' file; do
  lines=$(wc -l < "$file")
  if (( lines > MAX_LINES )); then
    violations+=("$lines $file")
  fi
done < <(find vyre-core vyre-wgpu vyre-reference vyre-primitives vyre-std vyre-macros vyre-spec vyre-sigstore vyre-dialect-crypto \
  -type d \( -name target -o -name fuzz \) -prune -o \
  -type f -name "*.rs" -print0 2>/dev/null || true)

if [[ ${#violations[@]} -gt 0 ]]; then
  printf 'Layout Law: %d .rs file(s) exceed %d lines (sorted descending):\n' \
    "${#violations[@]}" "$MAX_LINES" >&2
  printf '%s\n' "${violations[@]}" | sort -rn | head -30 >&2
  printf '\n  Fix: split each file so every module has one responsibility.\n' >&2
  printf '       `mod X` in `X.rs` is the canonical layout; factor cohesive\n' >&2
  printf '       sections into named sub-modules.\n' >&2
  if [[ "$STRICT" == "1" ]]; then
    exit 1
  fi
  echo '(informational mode — set VYRE_LAW_STRICT=1 to fail the build)' >&2
  exit 0
fi

echo "Layout Law: every .rs file ≤ ${MAX_LINES} lines."

#!/usr/bin/env bash
# Phase 8 tracker: count remaining naga::front::wgsl::parse_str call sites.
#
# vyre-core must not parse WGSL source back into naga::Module. Every
# dialect lowering should build the naga::Module programmatically via
# the shared builder family in vyre-wgpu.
#
# This script enumerates the remaining sites so migration progress is
# visible; it is informational (not a hard gate) until Phase 8 lands
# the last migration, at which point the script flips to exit-1 on
# any remaining occurrence.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Files allowed to use parse_str (vyre-wgpu naga integration + tests).
allow='(vyre-wgpu/|scripts/|tests/|benches/|docs/|\.md$)'

mapfile -t offenders < <(
  grep -rln 'parse_str' --include='*.rs' --exclude-dir=target --exclude-dir=.git "$REPO_ROOT" 2>/dev/null \
    | grep -Ev "$allow" \
    | sort -u
)

count=${#offenders[@]}
echo "Phase 8 migration tracker: $count file(s) still parse WGSL via parse_str"
if [[ "$count" -gt 0 ]]; then
  printf '  %s\n' "${offenders[@]}"
fi

# Non-zero exit once the migration is declared complete. Flip by removing
# the informational guard below and leaving only the `exit 1` path.
if [[ "${VYRE_STRICT_NO_PARSE_STR:-0}" = "1" ]]; then
  if [[ "$count" -gt 0 ]]; then
    echo "VYRE_STRICT_NO_PARSE_STR=1: failing because $count sites remain." >&2
    exit 1
  fi
fi

exit 0

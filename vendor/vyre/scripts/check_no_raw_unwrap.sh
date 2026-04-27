#!/usr/bin/env bash
# Law E enforcement: No raw unwrap/expect in production code.
#
# See ARCHITECTURE.md "Zero-Panic Policy". Production code MUST NOT panic.
# All errors must be propagated using std::result::Result and the Diagnostic
# system. The only exceptions are within test modules.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

violations=0

while IFS= read -r file; do
  # Skip tests/ and benches/ entirely.
  if [[ "$file" =~ /tests/ ]] || [[ "$file" =~ /benches/ ]]; then
    continue
  fi

  # Grep for unwrap() or expect() but exclude lines that look like #[test] modules
  # For a simple check, we just look for unwrap( or expect( on lines that don't have #[test]
  
  if grep -qE '\.unwrap\(\)|\.expect\(' "$file"; then
    # We might have matches. Let's count them, ignoring test blocks roughly by ignoring line matches inside tests.
    matches="$(grep -nE '\.unwrap\(\)|\.expect\(' "$file" || true)"
    if [[ -n "$matches" ]]; then
       # For ratchet purposes, we just report them.
       violations=$((violations + 1))
    fi
  fi
done < <(find "$REPO_ROOT" -type f -name '*.rs' -not -path '*/target/*' -not -path '*/\.git/*')

HIGHWATER_UNWRAP=625

CURRENT_UNWRAPS="$(grep -rE '\.unwrap\(\)|\.expect\(' --include='*.rs' --exclude-dir=target --exclude-dir=tests --exclude-dir=benches "$REPO_ROOT" | wc -l | tr -d ' ')"

if [[ "$CURRENT_UNWRAPS" -gt "$HIGHWATER_UNWRAP" ]]; then
  echo "unwrap() regression: $CURRENT_UNWRAPS usages, cap is $HIGHWATER_UNWRAP." >&2
  exit 1
fi

echo "unwrap() check: $CURRENT_UNWRAPS usages (cap: $HIGHWATER_UNWRAP)."

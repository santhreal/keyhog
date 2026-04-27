#!/usr/bin/env bash
# Law H — Every `unsafe` block carries a `// SAFETY:` comment on the
# line immediately above.
#
# Unsafe code is a contract between the author and the compiler. The
# contract has to be human-readable or the contract does not exist.
# `// SAFETY:` above every unsafe block is the standard established by
# the Rust project itself (rustc/std follow this convention exactly).
# We hold the same line.
#
# The guard rejects unsafe blocks without the comment. It also rejects
# `// SAFETY: TODO`, `// SAFETY: unclear`, `// SAFETY: investigate`
# and other cop-out comments that mean "we don't know yet".

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

violations=0

# Find every `unsafe {` occurrence in production source (not tests,
# not docs, not target/).
while IFS=: read -r file line; do
  # Read the two lines immediately above.
  prev_line="$(sed -n "$((line-1))p" "$file" 2>/dev/null || true)"
  prev_prev="$(sed -n "$((line-2))p" "$file" 2>/dev/null || true)"

  # Accept `// SAFETY:` on either preceding line.
  if echo "$prev_line" | grep -qE '//[[:space:]]*SAFETY:[[:space:]]+\S+' \
     || echo "$prev_prev" | grep -qE '//[[:space:]]*SAFETY:[[:space:]]+\S+'; then
    # Check for cop-out markers.
    if echo "$prev_line$prev_prev" | grep -qiE 'SAFETY:[[:space:]]*(TODO|FIXME|unclear|investigate|unknown|tbd|\?\?\?)'; then
      echo "LAW H VIOLATION: unsafe block at $file:$line has a cop-out SAFETY comment." >&2
      echo "  Preceding: $prev_line" >&2
      echo "  A SAFETY: comment that says 'TODO' or 'unclear' is worse than no comment — it promises a justification that does not exist." >&2
      echo "  Fix: write a real SAFETY justification explaining which invariants make this unsafe block sound." >&2
      echo "" >&2
      violations=$((violations + 1))
    fi
    continue
  fi

  echo "LAW H VIOLATION: unsafe block at $file:$line has no SAFETY comment." >&2
  echo "  Preceding line: $prev_line" >&2
  echo "  Every unsafe block must carry a \`// SAFETY: <justification>\` comment on the line immediately above." >&2
  echo "  Fix: add the comment explaining why the block is sound." >&2
  echo "" >&2
  violations=$((violations + 1))
done < <(grep -rn -E 'unsafe[[:space:]]*\{' --include='*.rs' "$REPO_ROOT" 2>/dev/null \
          | grep -vE '/target/|/\.git/|tests/|benches/|/docs/' \
          | awk -F: '{print $1 ":" $2}')

if [[ "$violations" -gt 0 ]]; then
  echo "Law H failed: $violations unsafe block(s) without SAFETY justification." >&2
  echo "Unsafe code is a contract that must be human-readable." >&2
  exit 1
fi

echo "Law H: every unsafe block has a SAFETY justification."

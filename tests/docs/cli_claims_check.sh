#!/usr/bin/env bash
#
# Docs CLI-claim regression gate (denylist).
#
# crates/scanner/tests/readme_claims.rs gates the README's NUMERIC claims
# (899 detectors, pattern counts, ...). Nothing gated the mdBook (docs/src)
# and marketing site (site/pages) CLI surface - which is exactly where these
# hallucinated flags shipped and pointed users at commands that error:
#
#   --disable-detectors / --enable-detectors  no per-ID toggle exists; the real
#                                             control is --detectors <dir>
#   --insecure-tls                            the real flag is --insecure
#   --source-type                             the real flag is --source
#   --quiet (on `keyhog scan`)                no such flag; the machine output
#                                             formats are already findings-only
#
# This guard asserts that CLI surface confirmed NOT to exist is never claimed
# as usable in the user docs. It is intentionally a precise denylist rather
# than a full `--help` diff: a regex sweep over prose mis-attributes neighbour
# flags (e.g. `cargo test -p keyhog-scanner --lib` is not a keyhog flag), which
# would make CI non-deterministic. The exhaustive flag cross-check belongs in
# a binary-driven test (see readme_claims.rs) where --help is ground truth.
#
# If an entry below becomes a real flag, IMPLEMENT it and delete its line here
# in the same change. Lines that DOCUMENT THE ABSENCE of a flag ("there is no
# --x", roadmap items) are legitimate and excluded.
#
# Run: bash tests/docs/cli_claims_check.sh

set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCS=("$ROOT/README.md" "$ROOT/docs/src" "$ROOT/site/pages")
fail=0

# Confirmed-nonexistent CLI surface. `keyhog scan --quiet` (not bare --quiet,
# which collides with other tools' flags in prose) is matched specifically.
DENY_FLAGS=(
  "--disable-detectors"
  "--enable-detectors"
  "--insecure-tls"
  "--source-type"
)
absence_re='roadmap|queued for|does not|do not|never|there is no|no per-ID|not a flag|no .* flag'

for bad in "${DENY_FLAGS[@]}"; do
  hits=$(grep -rn -- "$bad" "${DOCS[@]}" 2>/dev/null | grep -vEi "$absence_re")
  if [ -n "$hits" ]; then
    echo "FAIL: '$bad' does not exist in the keyhog CLI but is claimed in docs:"
    printf '%s\n' "$hits" | sed 's/^/    /'
    fail=1
  fi
done

# `--quiet` only as a keyhog scan flag (avoid matching unrelated prose).
qhits=$(grep -rn 'keyhog scan[^`<]*--quiet' "${DOCS[@]}" 2>/dev/null | grep -vEi "$absence_re")
if [ -n "$qhits" ]; then
  echo "FAIL: 'keyhog scan --quiet' is documented but no --quiet flag exists (machine formats are findings-only):"
  printf '%s\n' "$qhits" | sed 's/^/    /'
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "docs CLI-claim gate: PASS (no nonexistent CLI surface claimed in docs)"
else
  echo "docs CLI-claim gate: FAIL (fix the doc, or implement the flag + delete its denylist line)"
fi
exit "$fail"

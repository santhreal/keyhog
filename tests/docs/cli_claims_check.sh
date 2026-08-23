#!/usr/bin/env bash
#
# Docs CLI-claim regression gate (denylist).
#
# crates/scanner/tests/readme_claims.rs gates the README's NUMERIC claims
# (899 detectors, pattern counts, ...). Nothing gated the mdBook (docs/src)
# CLI surface. This is where hallucinated flags can point users at commands
# that error:
#
#   --disable-detectors / --enable-detectors  no per-ID toggle exists; the real
#                                             control is --detectors <dir>
#   --insecure-tls                            the real flag is --insecure
#   --source-type                             the real flag is --source
#
# This guard covers PROSE, where a flag is often named in order to say it does
# not exist. It is a precise denylist rather than a regex sweep because prose
# mis-attributes neighbour flags (e.g. `cargo test -p keyhog-scanner --lib` is
# not a keyhog flag), which would make CI non-deterministic.
#
# The exhaustive cross-check now exists and covers FENCED COMMANDS:
# crates/cli/tests/gate/docs_cli_surface.rs walks every `keyhog …` invocation
# in README.md and docs/src and checks its subcommand path and long flags
# against the compiled clap model.
#
# If an entry below becomes a real flag, IMPLEMENT it and delete its line here
# in the same change. Lines that DOCUMENT THE ABSENCE of a flag ("there is no
# --x", roadmap items) are legitimate and excluded.
#
# Run: bash tests/docs/cli_claims_check.sh

set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCS=("$ROOT/README.md" "$ROOT/docs/src")
fail=0

# Confirmed-nonexistent CLI surface.
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


if [ "$fail" -eq 0 ]; then
  echo "docs CLI-claim gate: PASS (no nonexistent CLI surface claimed in docs)"
else
  echo "docs CLI-claim gate: FAIL (fix the doc, or implement the flag + delete its denylist line)"
fi
exit "$fail"

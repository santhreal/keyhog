#!/usr/bin/env bash
# Materialize the legendary plan's generative breadth (docs/legendary/95) into a
# concrete, executable backlog: one row per (target × contract test-type).
#
# Reads the REAL registries (detectors/*.toml, the decode/source/subcommand dirs)
# so the backlog tracks the codebase, never a stale hand-list. Re-run on any
# detector/source/subcommand addition (KH-L-1079).
#
#   scripts/materialize-backlog.sh            # writes docs/legendary/99_BACKLOG.tsv
#   scripts/materialize-backlog.sh --count    # just print the row count
#
# Row: KH-G-NNNNN \t vector \t subsystem \t target \t test-type \t status(todo)
set -uo pipefail
cd "$(dirname "$0")/.."

OUT="docs/legendary/99_BACKLOG.tsv"
DET_DIR="crates/core/detectors"
n=0
tmp="$(mktemp)"

emit() { # vector subsystem target test-type
  n=$((n+1))
  printf 'KH-G-%05d\t%s\t%s\t%s\t%s\ttodo\n' "$n" "$1" "$2" "$3" "$4" >>"$tmp"
}

# --- detectors × contract test-types (the bulk) ----------------------------
for f in "$DET_DIR"/*.toml; do
  [ -e "$f" ] || continue
  id="$(basename "$f" .toml)"
  for tt in positive_truth negative_twin adversarial_evasion cross_file; do
    emit "TC,AV12" "DETECTORS" "$id" "$tt"
  done
  # checksummed detectors get a valid+invalid pair
  if grep -qiE 'checksum|luhn|crc|mod[ _]?10|base62' "$f" 2>/dev/null; then
    emit "L6,TC" "CHECKSUM" "$id" "checksum_valid"
    emit "L6,TC" "CHECKSUM" "$id" "checksum_invalid"
  fi
done

# --- decoders × contract ----------------------------------------------------
for d in base64 url hex unicode_escape quoted_printable mime html_entity json caesar reverse octal percent gzip; do
  for tt in recall negative nested_compound bomb_safe differential_oracle; do
    emit "TC,AV12" "DECODE" "$d" "$tt"
  done
done

# --- sources × contract (derived from the sources crate) --------------------
for s in $(ls crates/sources/src/*.rs 2>/dev/null | sed 's#.*/##;s/\.rs$//' | grep -vE '^(lib|mod|read|filter)$'); do
  for tt in positive negative error_exit_code scale adversarial; do
    emit "TC,AV12" "SOURCES" "$s" "$tt"
  done
  case "$s" in web|http|s3|github_org|slack|har|ssrf) emit "VR1,AV15" "SOURCES" "$s" "ssrf_blocked";; esac
done

# --- subcommands × contract (derived from the cli crate) --------------------
for c in $(ls crates/cli/src/subcommands/*.rs 2>/dev/null | sed 's#.*/##;s/\.rs$//' | grep -vE '^mod$'); do
  for tt in defaults flag_combos error_exit_code help_matches_behavior; do
    emit "TC,AV12" "CLI" "$c" "$tt"
  done
done

# --- output formats × contract ---------------------------------------------
for fmt in text json jsonl sarif; do
  for tt in schema_valid field_coherent redaction_correct; do
    emit "TC,AV10" "FORMAT" "$fmt" "$tt"
  done
done

# --- backend parity × corpus -----------------------------------------------
for b in cpu simd gpu megakernel; do
  for corp in empty edge chunk_boundary large decode_dense; do
    emit "TC,L8" "GPU" "$b" "parity_$corp"
  done
done

# --- cross-OS e2e ----------------------------------------------------------
for os in linux_x64 linux_arm64 macos_arm64 windows; do
  for surf in install doctor scan sarif tui hook uninstall; do
    emit "TC,AV13" "INSTALL" "$os" "$surf"
  done
done

if [ "${1:-}" = "--count" ]; then echo "$n rows"; rm -f "$tmp"; exit 0; fi

{
  echo "# KH-G backlog — materialized by scripts/materialize-backlog.sh (do not hand-edit; re-run to refresh)"
  echo "# id	vector	subsystem	target	test_type	status"
  sort -t$'\t' -k1,1 "$tmp"
} >"$OUT"
rm -f "$tmp"
echo "wrote $OUT: $n concrete backlog items"

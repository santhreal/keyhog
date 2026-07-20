#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <keyhog-binary> <cpu|simd>" >&2
  exit 2
fi

bin=$1
backend=$2
[[ -x "$bin" ]] || { echo "keyhog binary is not executable: $bin" >&2; exit 2; }
case "$backend" in
  cpu | simd) ;;
  *) echo "unsupported dogfood backend: $backend" >&2; exit 2 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# KH-1303: scan tree is only fixtures; reports live under outputs/ so the
# scanner never reads its own growing JSON/JSONL as input.
scan_tree="$tmp/scan"
out="$tmp/outputs"
mkdir -p "$scan_tree" "$out"

# Assemble known-positive shapes only at runtime so the dogfood harness cannot
# itself become a tracked secret-shaped fixture.
prefix="sk_$(printf live)"
secret_one="${prefix}_$(printf 'DogfoodOneA1B2C3D4E5F6G7H8')"
secret_two="${prefix}_$(printf 'DogfoodTwoJ9K8L7M6N5P4Q3R2')"
hidden_secret="${prefix}_$(printf 'IgnoredOnlyZ1Y2X3W4V5U6T7S8')"

printf 'TOKEN=%s\n' "$secret_one" >"$scan_tree/visible.env"
printf 'TOKEN=%s\n' "$hidden_secret" >"$scan_tree/hidden.env"
printf 'path:hidden.env\n' >"$scan_tree/.keyhogignore"

common=(scan --no-config --backend "$backend" --daemon=off --no-suppress-test-fixtures)

assert_redacted() {
  local secret=$1
  local report=$2
  if grep -Fq "$secret" "$report"; then
    echo "plaintext credential leaked into report: $report" >&2
    exit 1
  fi
}

assert_report() {
  local filter=$1
  local report=$2
  local contract=$3
  if ! jq -e "$filter" "$report" >/dev/null; then
    echo "$contract: $report" >&2
    jq . "$report" >&2 || true
    exit 1
  fi
}

# A real ignore file suppresses only the named sibling; the visible finding,
# exact detector, and path survive. Operational failures are never accepted as
# an empty report.
set +e
"$bin" "${common[@]}" --format json "$scan_tree" >"$out/exclude.json" 2>"$out/exclude.err"
rc=$?
set -e
[[ $rc -eq 1 ]] || { cat "$out/exclude.err" >&2; echo "exclude scan exited $rc, expected 1" >&2; exit 1; }
assert_report \
  'length == 1 and .[0].detector_id == "stripe-secret-key" and (.[0].location.file_path | endswith("visible.env"))' \
  "$out/exclude.json" "exclude scan did not preserve exactly the visible Stripe finding"
assert_redacted "$secret_one" "$out/exclude.json"
assert_redacted "$hidden_secret" "$out/exclude.json"

# Baseline creation is an explicit reviewed state transition. The same finding
# becomes clean; adding one new credential yields exactly that new tuple.
"$bin" "${common[@]}" --create-baseline "$out/baseline.json" --format json \
  "$scan_tree/visible.env" >"$out/create-baseline.json" 2>"$out/create-baseline.err"
set +e
"$bin" "${common[@]}" --baseline "$out/baseline.json" --format json \
  "$scan_tree/visible.env" >"$out/known.json" 2>"$out/known.err"
rc=$?
set -e
[[ $rc -eq 0 ]] || { cat "$out/known.err" >&2; echo "baseline rescan exited $rc, expected 0" >&2; exit 1; }
assert_report 'type == "array" and length == 0' "$out/known.json" \
  "baseline rescan did not suppress the reviewed finding"

printf 'TOKEN=%s\n' "$secret_two" >"$scan_tree/new.env"
set +e
"$bin" "${common[@]}" --baseline "$out/baseline.json" --format json \
  "$scan_tree" >"$out/new-only.json" 2>"$out/new-only.err"
rc=$?
set -e
[[ $rc -eq 1 ]] || { cat "$out/new-only.err" >&2; echo "new-finding scan exited $rc, expected 1" >&2; exit 1; }
assert_report \
  'length == 1 and .[0].detector_id == "stripe-secret-key" and (.[0].location.file_path | endswith("new.env"))' \
  "$out/new-only.json" "baseline scan did not isolate exactly the new Stripe finding"
assert_redacted "$secret_two" "$out/new-only.json"

# JSONL is a distinct reporter contract: one valid object per finding and no
# plaintext credential. The clean/SARIF reporters are exercised by ci.yml.
set +e
"$bin" "${common[@]}" --format jsonl "$scan_tree/visible.env" \
  >"$out/finding.jsonl" 2>"$out/finding-jsonl.err"
rc=$?
set -e
[[ $rc -eq 1 ]] || { cat "$out/finding-jsonl.err" >&2; echo "JSONL scan exited $rc, expected 1" >&2; exit 1; }
if ! jq -se 'length == 1 and .[0].detector_id == "stripe-secret-key"' \
  "$out/finding.jsonl" >/dev/null; then
  echo "JSONL reporter did not emit exactly one canonical Stripe finding" >&2
  jq -s . "$out/finding.jsonl" >&2 || true
  exit 1
fi
assert_redacted "$secret_one" "$out/finding.jsonl"

# Stdin uses the same detector and exit contract without filesystem metadata.
set +e
printf 'TOKEN=%s\n' "$secret_one" \
  | "$bin" "${common[@]}" --stdin --format json >"$out/stdin.json" 2>"$out/stdin.err"
rc=$?
set -e
[[ $rc -eq 1 ]] || { cat "$out/stdin.err" >&2; echo "stdin scan exited $rc, expected 1" >&2; exit 1; }
assert_report 'length == 1 and .[0].detector_id == "stripe-secret-key"' \
  "$out/stdin.json" "stdin reporter did not emit exactly one canonical Stripe finding"
assert_redacted "$secret_one" "$out/stdin.json"

# Decode-through is exercised on a bounded runtime fixture instead of relying
# on the repository's deliberately adversarial decoder corpora. The report must
# retain the canonical detector and never disclose the decoded plaintext.
encoded=$(printf 'TOKEN=%s\n' "$secret_one" | base64 | tr -d '\n')
# Keep decode fixture outside the multi-file scan roots so new-only baseline
# scans never pick it up as an extra finding (KH-1403).
printf 'payload=%s\n' "$encoded" >"$out/encoded.txt"
set +e
"$bin" "${common[@]}" --format json "$out/encoded.txt" \
  >"$out/decoded.json" 2>"$out/decoded.err"
rc=$?
set -e
[[ $rc -eq 1 ]] || { cat "$out/decoded.err" >&2; echo "decode-through scan exited $rc, expected 1" >&2; exit 1; }
assert_report 'length == 1 and .[0].detector_id == "stripe-secret-key"' \
  "$out/decoded.json" "decode-through did not emit exactly one canonical Stripe finding"
assert_redacted "$secret_one" "$out/decoded.json"

# Precision owns decoding and SARIF together on a bounded production-shaped
# input. This avoids weakening repository coverage around its intentional
# decoder-bomb corpus while proving the policy preset and reporter contract.
set +e
"$bin" "${common[@]}" --precision --format sarif "$scan_tree/visible.env" \
  >"$out/precision.sarif" 2>"$out/precision.err"
rc=$?
set -e
[[ $rc -eq 1 ]] || { cat "$out/precision.err" >&2; echo "precision SARIF scan exited $rc, expected 1" >&2; exit 1; }
assert_report \
  '.version == "2.1.0" and ([.runs[].results[]?] | length == 1) and .runs[0].results[0].ruleId == "stripe-secret-key"' \
  "$out/precision.sarif" "precision SARIF did not emit exactly one canonical Stripe finding"
assert_redacted "$secret_one" "$out/precision.sarif"

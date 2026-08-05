#!/usr/bin/env bash
# Exercise a real repository scan and validate both the report and dogfood trace.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <keyhog-binary> <cpu|simd> <json|sarif> <report>" >&2
  exit 2
fi

binary=$1
backend=$2
format=$3
report=$4
trace="${report}.trace.log"

case "$backend" in
  cpu | simd) ;;
  *) echo "unsupported dogfood backend: $backend" >&2; exit 2 ;;
esac

case "$format" in
  json | sarif) ;;
  *) echo "unsupported dogfood report format: $format" >&2; exit 2 ;;
esac

set +e
"$binary" scan . --no-config --backend "$backend" --daemon=off --dogfood --no-decode \
  --format "$format" --output "$report" 2>"$trace"
scan_status=$?
set -e

if [[ $scan_status -ne 0 ]]; then
  echo "repository dogfood failed: backend=$backend format=$format exit=$scan_status" >&2
  if [[ -s "$report" ]]; then
    case "$format" in
      json)
        jq -r '.[] | "\(.detector_id) \(.location.file_path):\(.location.line) \(.credential_redacted)"' \
          "$report" >&2 || true
        ;;
      sarif)
        jq -r '.runs[].results[]? | "\(.ruleId) \(.locations[0].physicalLocation.artifactLocation.uri // "<unknown>")"' \
          "$report" >&2 || true
        ;;
    esac
  fi
  grep -E '(^error:| WARN |^WARN |^FAIL )' "$trace" | head -n 40 >&2 || true
  exit "$scan_status"
fi

case "$format" in
  json)
    jq -e 'type == "array" and length == 0' "$report" >/dev/null
    ;;
  sarif)
    jq -e '.version == "2.1.0" and ([.runs[].results[]?] | length == 0)' \
      "$report" >/dev/null
    ;;
esac

# The absence of FAIL lines is a NEGATIVE claim, so it is only worth anything
# if the trace could have carried one. An empty or missing trace makes this
# grep return "no failures" and the lane pass while having examined nothing,
# which is the same success-equals-failure shape the dogfood lanes exist to
# catch. Require the input to exist and be non-empty first.
if [[ ! -s "$trace" ]]; then
  echo "dogfood trace is empty or missing at $trace; the coverage check below" >&2
  echo "would pass without examining anything. Refusing to report success." >&2
  exit 1
fi

if grep -q '^FAIL ' "$trace"; then
  echo "dogfood coverage failure for backend=$backend" >&2
  grep '^FAIL ' "$trace" >&2
  exit 1
fi

tail -n 1 "$trace" | jq -e '
  (.dogfood.example_suppressions_total | type == "number") and
  (.dogfood.events | type == "array")
' >/dev/null

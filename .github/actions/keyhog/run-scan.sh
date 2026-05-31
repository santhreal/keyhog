#!/usr/bin/env bash
set -uo pipefail

scan_path="${KEYHOG_SCAN_PATH:-.}"
severity="${KEYHOG_SEVERITY:-high}"
format="${KEYHOG_FORMAT:-sarif}"
report="${KEYHOG_OUTPUT:-keyhog-results.sarif}"
verify="${KEYHOG_VERIFY:-false}"
baseline="${KEYHOG_BASELINE:-}"

case "$severity" in
  info | low | medium | high | critical) ;;
  *)
    echo "::error title=KeyHog::Invalid severity '$severity'. Use one of: info, low, medium, high, critical."
    exit 2
    ;;
esac

case "$format" in
  sarif | json | jsonl | text) ;;
  *)
    echo "::error title=KeyHog::Invalid format '$format'. Use one of: sarif, json, jsonl, text."
    exit 2
    ;;
esac

case "$verify" in
  true | false) ;;
  *)
    echo "::error title=KeyHog::Invalid verify '$verify'. Use 'true' or 'false'."
    exit 2
    ;;
esac

args=(scan
  --path "$scan_path"
  --severity "$severity"
  --format "$format"
  --output "$report")

if [[ "$verify" == "true" ]]; then
  args+=(--verify)
fi

if [[ -n "$baseline" ]]; then
  args+=(--baseline "$baseline")
fi

set +e
keyhog "${args[@]}"
keyhog_exit=$?
set -e

count_from_report() {
  local report_format="$1"
  local report_path="$2"

  case "$report_format" in
    sarif)
      if command -v jq >/dev/null 2>&1; then
        jq '[.runs[].results[]] | length' "$report_path"
      elif command -v python3 >/dev/null 2>&1; then
        python3 - "$report_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    sarif = json.load(f)

print(sum(len(run.get("results", [])) for run in sarif.get("runs", [])))
PY
      else
        return 2
      fi
      ;;
    json)
      if command -v jq >/dev/null 2>&1; then
        jq 'length' "$report_path"
      elif command -v python3 >/dev/null 2>&1; then
        python3 - "$report_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    report = json.load(f)

if not isinstance(report, list):
    raise SystemExit("keyhog JSON report must be a top-level array")

print(len(report))
PY
      else
        return 2
      fi
      ;;
    jsonl)
      awk 'END { print NR + 0 }' "$report_path"
      ;;
    text)
      grep -c 'Secret:' "$report_path" 2>/dev/null || true
      ;;
  esac
}

findings=0
if [[ -f "$report" ]]; then
  if parsed_findings="$(count_from_report "$format" "$report" 2>/dev/null)"; then
    findings="$parsed_findings"
  elif [[ "$keyhog_exit" == "1" || "$keyhog_exit" == "10" ]]; then
    findings=1
    echo "::warning title=KeyHog::Could not parse '$report'; keyhog exited $keyhog_exit, so treating the scan as having findings."
  else
    echo "::error title=KeyHog::Could not parse clean scan report '$report'."
    exit 3
  fi
elif [[ "$keyhog_exit" == "1" || "$keyhog_exit" == "10" ]]; then
  echo "::error title=KeyHog::keyhog reported findings but did not write '$report'."
  exit 3
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "findings=$findings"
    echo "exit-code=$keyhog_exit"
  } >> "$GITHUB_OUTPUT"
fi

echo "::notice title=KeyHog::Found $findings finding(s) at or above '$severity' severity."

if [[ "$keyhog_exit" != "0" && "$keyhog_exit" != "1" && "$keyhog_exit" != "10" ]]; then
  echo "::error title=KeyHog::keyhog exited $keyhog_exit (not a findings code) - treating as a scan failure"
  exit "$keyhog_exit"
fi

if [[ "$keyhog_exit" == "10" ]]; then
  echo "::error title=KeyHog::LIVE credential(s) confirmed by --verify (exit 10)."
fi

md_cell() {
  local value="$1"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  value="${value//|/\\|}"
  value="${value//\`/\\\`}"
  printf '`%s`' "$value"
}

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### KeyHog scan"
    echo
    echo "| Field | Value |"
    echo "| --- | --- |"
    printf '| Path | %s |\n' "$(md_cell "$scan_path")"
    printf '| Severity floor | %s |\n' "$(md_cell "$severity")"
    printf '| Format | %s |\n' "$(md_cell "$format")"
    printf '| Report | %s |\n' "$(md_cell "$report")"
    printf '| Findings | %s |\n' "$(md_cell "$findings")"
    printf '| Exit code | %s |\n' "$(md_cell "$keyhog_exit")"
    if [[ -n "$baseline" ]]; then
      printf '| Baseline | %s |\n' "$(md_cell "$baseline")"
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

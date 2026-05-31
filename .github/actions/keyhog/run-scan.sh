#!/usr/bin/env bash
set -uo pipefail

scan_path="${KEYHOG_SCAN_PATH:-.}"
severity="${KEYHOG_SEVERITY:-high}"
format="${KEYHOG_FORMAT:-sarif}"
report="${KEYHOG_OUTPUT:-keyhog-results.sarif}"
verify="${KEYHOG_VERIFY:-false}"
baseline="${KEYHOG_BASELINE:-}"
fail_on_findings="${KEYHOG_FAIL_ON_FINDINGS:-true}"
upload_sarif="${KEYHOG_UPLOAD_SARIF:-true}"

gha_escape() {
  local value="$1"
  value="${value//%/%25}"
  value="${value//$'\r'/%0D}"
  value="${value//$'\n'/%0A}"
  printf '%s' "$value"
}

gha_error() {
  printf '::error title=KeyHog::%s\n' "$(gha_escape "$1")"
}

gha_warning() {
  printf '::warning title=KeyHog::%s\n' "$(gha_escape "$1")"
}

gha_notice() {
  printf '::notice title=KeyHog::%s\n' "$(gha_escape "$1")"
}

now_ms() {
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    local seconds="${EPOCHREALTIME%.*}"
    local micros="${EPOCHREALTIME#*.}"
    micros="${micros}000000"
    micros="${micros:0:6}"
    printf '%s\n' "$((10#$seconds * 1000 + 10#$micros / 1000))"
    return
  fi

  local nanos
  nanos="$(date +%s%N 2>/dev/null || true)"
  if [[ "$nanos" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$((10#$nanos / 1000000))"
  else
    printf '%s000\n' "$(date +%s)"
  fi
}

case "$severity" in
  info | low | medium | high | critical) ;;
  *)
    gha_error "Invalid severity '$severity'. Use one of: info, low, medium, high, critical."
    exit 2
    ;;
esac

case "$format" in
  sarif | json | jsonl | text) ;;
  *)
    gha_error "Invalid format '$format'. Use one of: sarif, json, jsonl, text."
    exit 2
    ;;
esac

case "$verify" in
  true | false) ;;
  *)
    gha_error "Invalid verify '$verify'. Use 'true' or 'false'."
    exit 2
    ;;
esac

case "$fail_on_findings" in
  true | false) ;;
  *)
    gha_error "Invalid fail-on-findings '$fail_on_findings'. Use 'true' or 'false'."
    exit 2
    ;;
esac

case "$upload_sarif" in
  true | false) ;;
  *)
    gha_error "Invalid upload-sarif '$upload_sarif'. Use 'true' or 'false'."
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

scan_start_ms="$(now_ms)"
set +e
keyhog "${args[@]}"
keyhog_exit=$?
set -e
scan_end_ms="$(now_ms)"
duration_ms="$((scan_end_ms - scan_start_ms))"
if (( duration_ms < 0 )); then
  duration_ms=0
fi

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
      if command -v jq >/dev/null 2>&1; then
        jq -s 'length' "$report_path"
      elif command -v python3 >/dev/null 2>&1; then
        python3 - "$report_path" <<'PY'
import json
import sys

count = 0
with open(sys.argv[1], "r", encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        json.loads(line)
        count += 1

print(count)
PY
      else
        return 2
      fi
      ;;
    text)
      grep -c 'Secret:' "$report_path" 2>/dev/null || true
      ;;
  esac
}

findings=0
if [[ "$keyhog_exit" != "0" && "$keyhog_exit" != "1" && "$keyhog_exit" != "10" ]]; then
  gha_error "keyhog exited $keyhog_exit (not a findings code) - treating as a scan failure"
  exit "$keyhog_exit"
fi

if [[ -f "$report" ]]; then
  if parsed_findings="$(count_from_report "$format" "$report" 2>/dev/null)"; then
    findings="$parsed_findings"
  elif [[ "$keyhog_exit" == "1" || "$keyhog_exit" == "10" ]]; then
    findings=1
    gha_warning "Could not parse '$report'; keyhog exited $keyhog_exit, so treating the scan as having findings."
  else
    gha_error "Could not parse clean scan report '$report'."
    exit 3
  fi
else
  gha_error "keyhog exited $keyhog_exit but did not write '$report'."
  exit 3
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "findings=$findings"
    echo "exit-code=$keyhog_exit"
    echo "duration-ms=$duration_ms"
  } >> "$GITHUB_OUTPUT"
fi

gha_notice "Found $findings finding(s) at or above '$severity' severity."
gha_notice "Scan completed in ${duration_ms} ms."

if [[ "$keyhog_exit" == "10" ]]; then
  gha_error "LIVE credential(s) confirmed by --verify (exit 10)."
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
    printf '| Duration | %s |\n' "$(md_cell "${duration_ms} ms")"
    printf '| Fail on findings | %s |\n' "$(md_cell "$fail_on_findings")"
    printf '| Upload SARIF | %s |\n' "$(md_cell "$upload_sarif")"
    if [[ -n "$baseline" ]]; then
      printf '| Baseline | %s |\n' "$(md_cell "$baseline")"
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

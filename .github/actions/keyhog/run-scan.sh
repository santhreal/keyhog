#!/usr/bin/env bash
set -uo pipefail

scan_path="."
severity="high"
format="sarif"
report="keyhog-results.sarif"
verify="false"
baseline=""
backend=""
autoroute_cache=""
cleanup_autoroute_cache=false
preset="default"
lockdown="false"
evidence_policy="default"
fail_on_findings="true"
upload_sarif="true"
print_effective_config=false

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

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --path)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --path"
        exit 2
      fi
      scan_path="$2"
      shift 2
      ;;
    --severity)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --severity"
        exit 2
      fi
      severity="$2"
      shift 2
      ;;
    --format)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --format"
        exit 2
      fi
      format="$2"
      shift 2
      ;;
    --output)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --output"
        exit 2
      fi
      report="$2"
      shift 2
      ;;
    --verify)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --verify"
        exit 2
      fi
      verify="$2"
      shift 2
      ;;
    --baseline)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --baseline"
        exit 2
      fi
      baseline="$2"
      shift 2
      ;;
    --backend)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --backend"
        exit 2
      fi
      backend="$2"
      shift 2
      ;;
    --autoroute-cache)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --autoroute-cache"
        exit 2
      fi
      autoroute_cache="$2"
      shift 2
      ;;
    --cleanup-autoroute-cache)
      cleanup_autoroute_cache=true
      shift
      ;;
    --preset)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --preset"
        exit 2
      fi
      preset="$2"
      shift 2
      ;;
    --lockdown)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --lockdown"
        exit 2
      fi
      lockdown="$2"
      shift 2
      ;;
    --evidence-policy)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --evidence-policy"
        exit 2
      fi
      evidence_policy="$2"
      shift 2
      ;;
    --fail-on-findings)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --fail-on-findings"
        exit 2
      fi
      fail_on_findings="$2"
      shift 2
      ;;
    --upload-sarif)
      if [[ "$#" -lt 2 ]]; then
        gha_error "Missing value for run-scan.sh argument: --upload-sarif"
        exit 2
      fi
      upload_sarif="$2"
      shift 2
      ;;
    --print-effective-config)
      print_effective_config=true
      shift
      ;;
    *)
      gha_error "Unknown run-scan.sh argument: $1"
      exit 2
      ;;
  esac
done
keyhog_bin="${KEYHOG_BIN:-keyhog}"
if [[ -n "${KEYHOG_BIN:-}" ]]; then
  if [[ -z "${ACTION_RUNTIME:-}" || "$keyhog_bin" != "$ACTION_RUNTIME"/* || ! -f "$keyhog_bin" || -L "$keyhog_bin" ]]; then
    gha_error "The private KeyHog binary is missing or untrusted."
    exit 2
  fi
fi

if [[ "$cleanup_autoroute_cache" == "true" ]]; then
  if [[ -z "$autoroute_cache" || -z "${RUNNER_TEMP:-}" ]]; then
    gha_error "--cleanup-autoroute-cache requires --autoroute-cache under RUNNER_TEMP."
    exit 2
  fi
  case "$autoroute_cache" in
    "$RUNNER_TEMP"/*) ;;
    *) gha_error "Refusing to clean an autoroute cache outside RUNNER_TEMP."; exit 2 ;;
  esac
  if [[ ! -f "$autoroute_cache" || -L "$autoroute_cache" ]]; then
    gha_error "Refusing to clean a missing or untrusted autoroute cache."
    exit 2
  fi
  cleanup_requested_autoroute() {
    local owned_path
    for owned_path in "$autoroute_cache" "${autoroute_cache}.lock"; do
      if [[ -d "$owned_path" && ! -L "$owned_path" ]]; then
        gha_warning "Autoroute cleanup refused a directory at an owned file path."
      elif [[ -e "$owned_path" || -L "$owned_path" ]]; then
        rm -f -- "$owned_path"
      fi
    done
  }
  trap cleanup_requested_autoroute EXIT
fi


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

scan_status_for_exit() {
  case "$1" in
    0 | 1 | 10) printf 'success\n' ;;
    13)
      if [[ "${2:-false}" == "true" ]]; then
        printf 'partial\n'
      else
        printf 'failed\n'
      fi
      ;;
    130) printf 'cancelled\n' ;;
    *) printf 'failed\n' ;;
  esac
}

md_cell() {
  local value="$1"
  value="${value//&/\&amp;}"
  value="${value//</\&lt;}"
  value="${value//>/\&gt;}"
  value="${value//$'\r'/\&#13;}"
  value="${value//$'\n'/\&#10;}"
  value="${value//|/\&#124;}"
  printf '<code>%s</code>' "$value"
}

case "$severity" in
  info | client-safe | low | medium | high | critical) ;;
  *)
    gha_error "Invalid severity '$severity'. Use one of: info, client-safe, low, medium, high, critical."
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

case "$backend" in
  "" | auto | simd | cpu | gpu-cuda | gpu-wgpu) ;;
  *)
    gha_error "Invalid backend '$backend'. Use one of: auto, simd, cpu, gpu-cuda, gpu-wgpu."
    exit 2
    ;;
esac
preset_flag=""
case "$preset" in
  default) ;;
  fast | deep | precision)
    preset_flag="--$preset"
    ;;
  *)
    gha_error "Invalid preset '$preset'. Use one of: default, fast, deep, precision."
    exit 2
    ;;
esac

case "$lockdown" in
  true | false) ;;
  *)
    gha_error "Invalid lockdown '$lockdown'. Use 'true' or 'false'."
    exit 2
    ;;
esac

case "$evidence_policy" in
  default | paranoid) ;;
  *)
    gha_error "Invalid evidence-policy '$evidence_policy'. Use one of: default, paranoid."
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
if [[ -z "${RUNNER_TEMP:-}" ]]; then
  gha_error "The Action report receipt requires RUNNER_TEMP."
  exit 2
fi
action_receipt_root="${ACTION_RUNTIME:-$RUNNER_TEMP}"
action_receipt="$action_receipt_root/keyhog-action-report-$$.receipt"
if [[ -e "$action_receipt" || -L "$action_receipt" ]]; then
  gha_error "Refusing a pre-existing Action report receipt path."
  exit 2
fi
receipt_owned_sha=""
cleanup_action_state() {
  if [[ -n "$receipt_owned_sha" ]]; then
    if [[ -f "$action_receipt" && ! -L "$action_receipt" ]]; then
      current_receipt_sha=""
      if command -v sha256sum >/dev/null 2>&1; then
        read -r current_receipt_sha _ < <(sha256sum < "$action_receipt")
      elif command -v shasum >/dev/null 2>&1; then
        read -r current_receipt_sha _ < <(shasum -a 256 < "$action_receipt")
      fi
      if [[ "$current_receipt_sha" == "$receipt_owned_sha" ]]; then
        rm -f -- "$action_receipt"
      else
        gha_warning "Action report receipt changed after verification; refusing cleanup."
      fi
    elif [[ -e "$action_receipt" || -L "$action_receipt" ]]; then
      gha_warning "Action report receipt changed type after verification; refusing cleanup."
    fi
  fi
  if [[ "$cleanup_autoroute_cache" == "true" ]]; then
    cleanup_requested_autoroute
  fi
}
trap cleanup_action_state EXIT


evidence_policy_args=(--evidence-policy "$evidence_policy")
if [[ "${ACTION_RELEASE_REQUIRED:-false}" == "true" ]]; then
  set +e
  evidence_help="$("$keyhog_bin" scan --help 2>&1)"
  evidence_help_exit=$?
  set -e
  if [[ "$evidence_help_exit" != "0" ]]; then
    gha_error "Published keyhog could not report whether it supports --evidence-policy."
    exit 2
  fi
  if [[ "$evidence_help" != *"--evidence-policy"* ]]; then
    if [[ "$evidence_policy" != "paranoid" ]]; then
      gha_error "Published keyhog lacks --evidence-policy and cannot implement the requested default blocking policy."
      exit 2
    fi
    evidence_policy_args=()
    gha_notice "Published keyhog predates --evidence-policy; its blocking behavior is equivalent to paranoid."
  fi
fi

args=(scan
  --path "$scan_path"
  --severity "$severity"
  --format "$format"
  --output "$report"
  --action-receipt "$action_receipt")
args+=("${evidence_policy_args[@]}")
config_args=(config
  --effective
  --path "$scan_path"
  --severity "$severity"
  --format "$format")
config_args+=("${evidence_policy_args[@]}")
if [[ "$verify" == "true" ]]; then
  config_args+=(--verify)
else
  config_args+=(--no-verify)
fi

if [[ -n "$backend" ]]; then
  config_args+=(--backend "$backend")
fi
if [[ -n "$preset_flag" ]]; then
  config_args+=("$preset_flag")
fi
if [[ "$lockdown" == "true" ]]; then
  config_args+=(--lockdown)
fi



if [[ "$verify" == "true" ]]; then
  args+=(--verify)
else
  args+=(--no-verify)
fi

if [[ -n "$backend" ]]; then
  args+=(--backend "$backend")
fi
if [[ -n "$autoroute_cache" ]]; then
  args+=(--autoroute-cache "$autoroute_cache")
  config_args+=(--autoroute-cache "$autoroute_cache")
fi
if [[ -n "$preset_flag" ]]; then
  args+=("$preset_flag")
fi
if [[ "$lockdown" == "true" ]]; then
  args+=(--lockdown)
fi


if [[ -n "$baseline" ]]; then
  args+=(--baseline "$baseline")
  config_args+=(--baseline "$baseline")
fi

if [[ "$print_effective_config" == "true" ]]; then
  set +e
  "$keyhog_bin" "${config_args[@]}"
  config_exit=$?
  set -e
  if [[ "$config_exit" != "0" ]]; then
    gha_warning "keyhog effective-config preflight exited $config_exit; continuing with the real scan so reports and SARIF are still produced."
  fi
fi

findings=0
report_present=false
scan_status=failed
receipt_written=false
scan_start_ms=""
duration_ms=0
keyhog_exit=3

publish_receipt() {
  if [[ "$receipt_written" == "true" ]]; then
    return
  fi
  receipt_written=true
  published_report_present=false
  if [[ -n "${snapshot_report:-}" && -n "${snapshot_sha256:-}" && -f "$snapshot_report" && ! -L "$snapshot_report" ]]; then
    published_report_present=true
  fi

  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
      printf 'findings=%s\n' "$findings"
      printf 'exit-code=%s\n' "$keyhog_exit"
      printf 'duration-ms=%s\n' "$duration_ms"
      printf 'scan-status=%s\n' "$scan_status"
      printf 'report-present=%s\n' "$published_report_present"
      printf 'report=%s\n' "${snapshot_report:-}"
      printf 'report-sha256=%s\n' "${snapshot_sha256:-}"
    } >> "$GITHUB_OUTPUT"
  fi

  gha_notice "scan status: $scan_status"
  if [[ "$findings" =~ ^[0-9]+$ ]]; then
    gha_notice "Found $findings finding(s) at or above '$severity' severity."
  else
    gha_notice "Finding count unavailable because the scan did not publish a valid report."
  fi
  gha_notice "Scan completed in ${duration_ms} ms."
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo '### KeyHog scan'
      echo
      echo '| Field | Value |'
      echo '| --- | --- |'
      printf '| Path | %s |\n' "$(md_cell "$scan_path")"
      printf '| Severity floor | %s |\n' "$(md_cell "$severity")"
      printf '| Format | %s |\n' "$(md_cell "$format")"
      printf '| Action preset input | %s |\n' "$(md_cell "$preset")"
      printf '| Action lockdown input | %s |\n' "$(md_cell "$lockdown")"
      printf '| Action verification input | %s |\n' "$(md_cell "$verify")"
      printf '| Report | %s |\n' "$(md_cell "$report")"
      printf '| Report present | %s |\n' "$(md_cell "$report_present")"
      printf '| Findings | %s |\n' "$(md_cell "${findings:-unavailable}")"
      printf '| Exit code | %s |\n' "$(md_cell "$keyhog_exit")"
      printf '| Completion status | %s |\n' "$(md_cell "$scan_status")"
      printf '| Duration | %s |\n' "$(md_cell "${duration_ms} ms")"
      printf '| Fail on findings | %s |\n' "$(md_cell "$fail_on_findings")"
      printf '| Upload SARIF | %s |\n' "$(md_cell "$upload_sarif")"
      if [[ -n "$baseline" ]]; then
        printf '| Baseline | %s |\n' "$(md_cell "$baseline")"
      fi
    } >> "$GITHUB_STEP_SUMMARY"
  fi
}

if [[ -z "$report" ]]; then
  findings=""
  keyhog_exit=2
  publish_receipt
  gha_error "Report output path must not be empty."
  exit 2
fi
if [[ -L "$report" ]]; then
  findings=""
  keyhog_exit=2
  publish_receipt
  gha_error "Refusing symlink report output '$report'."
  exit 2
fi
if [[ -e "$report" ]]; then
  if [[ ! -f "$report" ]] || ! rm -f -- "$report"; then
    findings=""
    keyhog_exit=2
    publish_receipt
    gha_error "Could not safely remove stale report output '$report'."
    exit 2
  fi
fi
if [[ -e "$report" || -L "$report" ]]; then
  findings=""
  keyhog_exit=2
  publish_receipt
  gha_error "Stale report output '$report' remained before the scan."
  exit 2
fi


scan_start_ms="$(now_ms)"
set +e
"$keyhog_bin" "${args[@]}"
keyhog_exit=$?
set -e
if [[ -f "$action_receipt" && ! -L "$action_receipt" ]]; then
  if command -v sha256sum >/dev/null 2>&1; then
    read -r receipt_owned_sha _ < <(sha256sum < "$action_receipt")
  elif command -v shasum >/dev/null 2>&1; then
    read -r receipt_owned_sha _ < <(shasum -a 256 < "$action_receipt")
  else
    receipt_owned_sha=""
  fi
fi
scan_end_ms="$(now_ms)"
duration_ms="$((scan_end_ms - scan_start_ms))"
if (( duration_ms < 0 )); then
  duration_ms=0
fi
if [[ -f "$report" && ! -L "$report" ]]; then
  report_present=true
fi
scan_status="$(scan_status_for_exit "$keyhog_exit" "$report_present")"

count_from_report() {
  local report_format="$1"
  local report_path="$2"
  "$keyhog_bin" action-report verify \
    --receipt "$action_receipt" \
    --report "$report_path" \
    --format "$report_format" \
    --exit-code "$keyhog_exit"
}

unexpected_exit=false
case "$keyhog_exit" in
  0 | 1 | 10) ;;
  *) unexpected_exit=true ;;
esac

if [[ "$report_present" == "true" ]]; then
  if parsed_findings="$(count_from_report "$format" "$report" 2>/dev/null)"; then
    findings="$parsed_findings"
  elif [[ "$unexpected_exit" == "true" ]]; then
    findings=""
    if [[ "$keyhog_exit" != "130" ]]; then
      scan_status=failed
    fi
  else
    scan_status=failed
    findings=""
    publish_receipt
    gha_error "Could not verify scan report receipt for '$report'; refusing to infer a finding count from exit $keyhog_exit."
    exit 3
  fi
elif [[ "$unexpected_exit" == "true" ]]; then
  findings=""
else
  scan_status=failed
  publish_receipt
  gha_error "keyhog exited $keyhog_exit but did not write '$report'."
  exit 3
fi

if [[ "$unexpected_exit" != "true" ]]; then
  if [[ ("$keyhog_exit" == "1" || "$keyhog_exit" == "10") && "$findings" == "0" ]]; then
    scan_status=failed
    publish_receipt
    gha_error "Contradictory scan result: keyhog exited $keyhog_exit but the report contains no findings."
    exit 3
  fi
fi

snapshot_report=""
snapshot_sha256=""
if [[ "$report_present" == "true" && -n "$findings" ]]; then
  snapshot_root="${ACTION_RUNTIME:-$RUNNER_TEMP}"
  if [[ ! -d "$snapshot_root" || -L "$snapshot_root" ]]; then
    scan_status=failed
    publish_receipt
    gha_error "Private report snapshot root is missing or untrusted."
    exit 3
  fi
  snapshot_dir="$(mktemp -d "$snapshot_root/report-snapshot.XXXXXXXX")"
  chmod 700 "$snapshot_dir"
  report_name="$(basename "$report")"
  snapshot_report="$snapshot_dir/$report_name"
  if [[ -e "$snapshot_report" || -L "$snapshot_report" ]]; then
    scan_status=failed
    publish_receipt
    gha_error "Refusing a pre-existing private report snapshot destination."
    exit 3
  fi
  set -o noclobber
  : > "$snapshot_report"
  set +o noclobber
  cat -- "$report" > "$snapshot_report"
  chmod 400 "$snapshot_report"
  if ! snapshot_findings="$(count_from_report "$format" "$snapshot_report" 2>/dev/null)" || [[ "$snapshot_findings" != "$findings" ]]; then
    scan_status=failed
    publish_receipt
    gha_error "Requested report changed while creating its receipt-bound private snapshot."
    exit 3
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    read -r snapshot_sha256 _ < <(sha256sum < "$snapshot_report")
  elif command -v shasum >/dev/null 2>&1; then
    read -r snapshot_sha256 _ < <(shasum -a 256 < "$snapshot_report")
  else
    scan_status=failed
    publish_receipt
    gha_error "No SHA-256 implementation is available to bind the private report snapshot."
    exit 2
  fi
fi

if [[ "$unexpected_exit" == "true" ]]; then
  publish_receipt
  gha_error "keyhog exited $keyhog_exit (not a findings code) - treating as a scan failure"
  exit "$keyhog_exit"
fi

publish_receipt

if [[ "$keyhog_exit" == "10" ]]; then
  gha_error "LIVE credential(s) confirmed by --verify (exit 10)."
  # Always fail the script on live credentials so standalone/script-only CI
  # cannot stay green when the composite fail step is skipped (KH-1331).
  exit 10
fi

if [[ "$scan_status" == "failed" ]]; then
  gha_error "Scan report validation failed; refusing to treat an unreadable findings report as advisory."
  exit 3
fi

# When fail-on-findings is true, propagate scanner exit 1. A non-empty report
# with scanner exit 0 contains visible review-tier findings and is valid.
if [[ "$fail_on_findings" == "true" && "$keyhog_exit" == "1" ]]; then
  gha_error "Found ${findings} policy-blocking finding(s) (fail-on-findings=true)."
  exit 1
fi

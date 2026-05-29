#!/usr/bin/env bash
#
# Docker integration scenario battery.
#
# Drives the REAL keyhog binary inside a pre-built image (arg $1) under
# spoofed hardware / env / edge cases, asserting exit code + stdout. Each row
# in SCENARIOS is one integration test; the (image x row) product is the
# matrix. Add a row to add a test - that is how this scales to hundreds.
#
# Row format (| separated):
#   name | env | args | want_exit | grep_contains | grep_forbids
#     env           space-separated KEY=VAL pairs, or "-" for none
#     args          arguments passed to `keyhog` inside the container
#     want_exit     expected process exit code
#     grep_contains substring that MUST appear in stdout+stderr, or "-"
#     grep_forbids  substring that must NOT appear, or "-"
#
# Exits non-zero if any scenario fails.

set -uo pipefail
IMAGE="${1:?usage: scenarios.sh <image-tag>}"

PASS=0
FAIL=0
FAILED=()

run_scenario() {
  local name="$1" env="$2" args="$3" want_exit="$4" want="$5" forbid="$6"
  local env_flags=()
  if [[ "$env" != "-" ]]; then
    local kv
    for kv in $env; do env_flags+=("-e" "$kv"); done
  fi

  local out rc ok=1
  # shellcheck disable=SC2086  # $args is intentionally word-split into argv.
  out="$(docker run --rm "${env_flags[@]}" "$IMAGE" keyhog $args 2>&1)"
  rc=$?

  if [[ "$rc" != "$want_exit" ]]; then
    ok=0
    echo "  ✗ [$name] exit code: want $want_exit, got $rc"
  fi
  if [[ "$want" != "-" ]] && ! grep -qF -- "$want" <<<"$out"; then
    ok=0
    echo "  ✗ [$name] stdout missing: '$want'"
  fi
  if [[ "$forbid" != "-" ]] && grep -qF -- "$forbid" <<<"$out"; then
    ok=0
    echo "  ✗ [$name] stdout contained forbidden: '$forbid'"
  fi

  if [[ "$ok" == 1 ]]; then
    PASS=$((PASS + 1))
    echo "  ✓ $name"
  else
    FAIL=$((FAIL + 1))
    FAILED+=("$name")
  fi
}

# name | env | args | want_exit | grep_contains | grep_forbids
SCENARIOS=(
  # --- core detection truth ---------------------------------------------
  "scan-aws-json|-|scan --format json /test/corpus/aws_leak.env|1|aws-access-key|-"
  "scan-clean-exit0|-|scan --format json /test/corpus/clean.txt|0|[]|aws-access-key"
  "scan-fp-trap-zero|-|scan --format json /test/corpus/fp_trap.txt|0|[]|detector_id"
  "scan-text-format|-|scan --format text /test/corpus/aws_leak.env|1|AWS Access Key|-"
  "scan-sarif-format|-|scan --format sarif /test/corpus/aws_leak.env|1|2.1.0|-"
  # --- hardware spoofing -------------------------------------------------
  "no-gpu-still-scans|KEYHOG_NO_GPU=1|scan --format json /test/corpus/aws_leak.env|1|aws-access-key|-"
  "require-gpu-fails-closed|KEYHOG_REQUIRE_GPU=1|scan /test/corpus/aws_leak.env|2|-|-"
  "single-thread-correct|KEYHOG_THREADS=1|scan --format json /test/corpus/aws_leak.env|1|aws-access-key|-"
  "many-threads-correct|KEYHOG_THREADS=64|scan --format json /test/corpus/aws_leak.env|1|aws-access-key|-"
  # --- diagnostics + surfaces -------------------------------------------
  "doctor-self-test-pass|-|doctor|0|PASS|-"
  "detectors-count|-|detectors|0|Loaded 891 detectors|-"
  "completion-bash|-|completion bash|0|_keyhog|-"
  "explain-detector|-|explain aws-access-key|0|AWS Access Key|-"
  "version|-|--version|0|KeyHog v|-"
  # --- edge cases / robustness ------------------------------------------
  "missing-path-exit2|-|scan /test/corpus/does_not_exist.env|2|-|-"
  "stdin-scan|-|scan --stdin|1|aws-access-key|-"  # corpus piped below via special-case
  "empty-dir-clean|-|scan /tmp|0|-|-"
  # On a GPU-less host the CPU-fallback notice must be ONE concise line, not
  # the full multi-line wgpu adapter-probe dump (regression guard for the
  # de-noised warning). 'Probed adapters' only appears in the verbose dump.
  "no-gpu-warning-concise|-|scan --format json /test/corpus/aws_leak.env|1|-|Probed adapters"
)

echo "== docker integration matrix: $IMAGE =="
for s in "${SCENARIOS[@]}"; do
  IFS='|' read -r n e a x g f <<<"$s"
  if [[ "$n" == "stdin-scan" ]]; then
    # stdin needs piped input; run specially rather than via docker run args.
    out="$(printf 'AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n' \
      | docker run --rm -i "$IMAGE" keyhog scan --stdin --format json 2>&1)"
    rc=$?
    if [[ "$rc" == 1 ]] && grep -qF -- "aws-access-key" <<<"$out"; then
      PASS=$((PASS + 1)); echo "  ✓ $n"
    else
      FAIL=$((FAIL + 1)); FAILED+=("$n"); echo "  ✗ [$n] exit=$rc, expected exit 1 + aws-access-key"
    fi
    continue
  fi
  run_scenario "$n" "$e" "$a" "$x" "$g" "$f"
done

# Dedicated assertion: piped (non-TTY) output must not contain raw ANSI
# escape sequences (the NO_COLOR/TTY discipline), which a plain grep -F can't
# express. doctor goes through the shared palette.
esc_out="$(docker run --rm "$IMAGE" keyhog doctor 2>&1)"
if grep -qP '\x1b\[' <<<"$esc_out"; then
  FAIL=$((FAIL + 1)); FAILED+=("doctor-piped-no-ansi"); echo "  ✗ [doctor-piped-no-ansi] raw ANSI escapes in non-TTY output"
else
  PASS=$((PASS + 1)); echo "  ✓ doctor-piped-no-ansi"
fi

echo
echo "== $IMAGE: $PASS passed, $FAIL failed =="
if [[ "$FAIL" != 0 ]]; then
  printf 'FAILED: %s\n' "${FAILED[*]}"
  exit 1
fi

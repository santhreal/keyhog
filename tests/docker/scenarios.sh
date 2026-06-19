#!/usr/bin/env bash
#
# Docker integration scenario battery.
#
# Drives the REAL keyhog binary inside a pre-built image (arg $1) and asserts
# exit code + stdout/stderr. Two layers:
#
#   1. INVARIANT matrix - a clear-cut real secret must be found (and clean /
#      placeholder input must stay clean) IDENTICALLY across every hardware /
#      strictness profile. This is a strong correctness property: detection
#      must not diverge under any *_STRICT toggle.
#      Coverage = INVARIANTS x ENV_PROFILES.
#   2. SURFACE battery - per-subcommand / per-format / edge-case checks run
#      once under the default env.
#
# The (image x INVARIANTS x ENV_PROFILES) + (image x SURFACES) product is the
# matrix; add a row to either table to add tests across every image.
#
# Exits non-zero if any check fails.

set -uo pipefail
IMAGE="${1:?usage: scenarios.sh <image-tag>}"

PASS=0
FAIL=0
FAILED=()

# Run `keyhog $args` in the image with the given space-separated env (or "-"),
# asserting exit code + a required / forbidden stdout+stderr substring.
check() {
  local name="$1" env="$2" args="$3" want_exit="$4" want="$5" forbid="$6"
  local env_flags=()
  if [[ "$env" != "-" ]]; then
    local kv
    for kv in $env; do env_flags+=("-e" "$kv"); done
  fi
  local out rc ok=1
  # shellcheck disable=SC2086
  out="$(docker run --rm "${env_flags[@]}" "$IMAGE" keyhog $args 2>&1)"
  rc=$?
  [[ "$rc" == "$want_exit" ]] || { ok=0; echo "  ✗ [$name] exit: want $want_exit got $rc"; }
  [[ "$want" == "-" ]] || grep -qF -- "$want" <<<"$out" || { ok=0; echo "  ✗ [$name] missing: '$want'"; }
  [[ "$forbid" == "-" ]] || ! grep -qF -- "$forbid" <<<"$out" || { ok=0; echo "  ✗ [$name] forbidden: '$forbid'"; }
  if [[ "$ok" == 1 ]]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); FAILED+=("$name"); fi
}

echo "== docker integration matrix: $IMAGE =="

# --- Layer 1: detection invariance across hardware/backend/strictness -------
# Each profile must NOT change the outcome of a clear-cut scan: a real AWS key
# is always found; ordinary prose and placeholder/example tokens never fire.
# A profile that breaks an invariant is a real backend/strictness bug.
ENV_PROFILES=(
  "default|-"
  "entropy-strict|KEYHOG_ENTROPY_STRICT=1"
  "noise-strict|KEYHOG_NOISE_STRICT=1"
  "unicode-strict|KEYHOG_UNICODE_STRICT=1"
  "whitespace-strict|KEYHOG_WHITESPACE_STRICT=1"
  "line-len-strict|KEYHOG_LINE_LEN_STRICT=1"
  "compound-strict|KEYHOG_COMPOUND_STRICT=1"
  "encoding-strict|KEYHOG_ENCODING_STRICT=1"
  "multi-strict|KEYHOG_MULTI_STRICT=1"
  "path-shape-strict|KEYHOG_PATH_SHAPE_STRICT=1"
  "comment-strict|KEYHOG_COMMENT_STRICT=1"
  "adversarial-strict|KEYHOG_ADVERSARIAL_STRICT=1"
)
# name | args | want_exit | grep | forbid
INVARIANTS=(
  "aws-found|scan --format json /test/corpus/aws_leak.env|1|aws-access-key|-"
  "clean-clean|scan --format json /test/corpus/clean.txt|0|[]|detector_id"
  "fp-trap-clean|scan --format json /test/corpus/fp_trap.txt|0|[]|detector_id"
)
for prof in "${ENV_PROFILES[@]}"; do
  IFS='|' read -r pname penv <<<"$prof"
  for inv in "${INVARIANTS[@]}"; do
    IFS='|' read -r iname iargs ix ig if_ <<<"$inv"
    check "inv:$pname/$iname" "$penv" "$iargs" "$ix" "$ig" "$if_"
  done
done

# --- Layer 2: per-surface checks (run once, default env) --------------------
# name | env | args | want_exit | grep | forbid
SURFACES=(
  "scan-text|-|scan --format text /test/corpus/aws_leak.env|1|AWS Access Key|-"
  "scan-jsonl|-|scan --format jsonl /test/corpus/aws_leak.env|1|aws-access-key|-"
  "scan-sarif|-|scan --format sarif /test/corpus/aws_leak.env|1|2.1.0|-"
  "scan-dir|-|scan --format json /test/corpus|1|aws-access-key|-"
  "scan-min-confidence|-|scan --min-confidence 0.0 --format json /test/corpus/aws_leak.env|1|aws-access-key|-"
  "scan-backend-simd|-|scan --backend simd --format json /test/corpus/aws_leak.env|1|aws-access-key|-"
  "scan-no-gpu|-|scan --no-gpu --format json /test/corpus/aws_leak.env|1|aws-access-key|-"
  "scan-threads-1|-|scan --threads 1 --format json /test/corpus/aws_leak.env|1|aws-access-key|-"
  "scan-threads-64|-|scan --threads 64 --format json /test/corpus/aws_leak.env|1|aws-access-key|-"
  "require-gpu-fails-closed|-|scan --require-gpu /test/corpus/aws_leak.env|12|-|-"
  "doctor-self-test|-|doctor|0|PASS|-"
  "detectors-count|-|detectors|0|Loaded 902 detectors|-"
  "explain-detector|-|explain aws-access-key|0|AWS Access Key|-"
  "completion-bash|-|completion bash|0|_keyhog|-"
  "completion-zsh|-|completion zsh|0|#compdef|-"
  "completion-fish|-|completion fish|0|keyhog|-"
  "backend-inspect|-|backend|0|hardware|-"
  "calibrate-noop|-|calibrate|0|detector counters|-"
  "hook-help-exit2|-|hook|2|install|-"
  "version|-|--version|0|KeyHog v|-"
  "help|-|--help|0|secret|-"
  "missing-path-exit2|-|scan /test/corpus/nope.env|2|-|detector_id"
  "empty-dir-clean|-|scan /tmp|0|-|-"
)
for s in "${SURFACES[@]}"; do
  IFS='|' read -r n e a x g f <<<"$s"
  check "surf:$n" "$e" "$a" "$x" "$g" "$f"
done

# --- Special cases that need stdin / read-only / escape handling ------------

# stdin scan (piped, not an arg).
out="$(printf 'AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n' \
  | docker run --rm -i "$IMAGE" keyhog scan --stdin --format json 2>&1)"
if [[ $? == 1 ]] && grep -qF aws-access-key <<<"$out"; then
  PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); FAILED+=("special:stdin-scan"); echo "  ✗ [special:stdin-scan]"; fi

# read-only root filesystem: a scan must still work (no scratch writes needed).
out="$(docker run --rm --read-only "$IMAGE" keyhog scan --format json /test/corpus/aws_leak.env 2>&1)"
if [[ $? == 1 ]] && grep -qF aws-access-key <<<"$out"; then
  PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); FAILED+=("special:read-only-fs"); echo "  ✗ [special:read-only-fs]"; fi

# Non-TTY output must carry no raw ANSI escape sequences.
if docker run --rm "$IMAGE" keyhog doctor 2>&1 | grep -qP '\x1b\['; then
  FAIL=$((FAIL + 1)); FAILED+=("special:no-ansi-piped"); echo "  ✗ [special:no-ansi-piped] raw ANSI in non-TTY output"
else PASS=$((PASS + 1)); fi

echo
echo "== $IMAGE: $PASS passed, $FAIL failed =="
if [[ "$FAIL" != 0 ]]; then
  printf 'FAILED: %s\n' "${FAILED[*]}"
  exit 1
fi

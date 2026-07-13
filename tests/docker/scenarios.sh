#!/usr/bin/env bash
#
# Docker integration scenario battery.
#
# Drives the REAL keyhog binary inside a pre-built image (arg $1) and asserts
# exit code + stdout/stderr. Two layers:
#
#   1. INVARIANT matrix - a clear-cut real secret must be found (and clean /
#      placeholder input must stay clean) IDENTICALLY across explicit backend /
#      scan-policy profiles. This is a strong correctness property: detection
#      must not diverge under real CLI controls.
#      Coverage = INVARIANTS x CLI_PROFILES.
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

# Some images ship a single-backend PORTABLE build (the musl/static image is built
# `--features portable`: no Hyperscan, no GPU). On such a build the `simd` backend
# does not exist, so `--backend simd` correctly errors instead of scanning. Probe
# the image's compiled backends once and skip the simd-specific scenarios there 
# they assert a backend this variant cannot have. This is a loud, recorded skip,
# never a silent pass. (Auto scans need no guard: a single-backend build resolves
# its lone backend directly, see `sole_compiled_backend` in dispatch/backend.rs 
# so it never fails closed and needs no calibration bake.)
if docker run --rm "$IMAGE" keyhog backend 2>&1 | grep -qE 'hyperscan: *compiled-in'; then
  HAS_SIMD=1
else
  HAS_SIMD=0
  echo "  ⓘ single-backend image (hyperscan absent): skipping the --backend simd scenarios"
fi

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

# --- Layer 1: detection invariance across backend / scan-policy profiles -----
# Each profile must NOT change the outcome of a clear-cut scan: a real AWS key
# is always found; ordinary prose and placeholder/example tokens never fire.
# A profile that breaks an invariant is a real backend/strictness bug.
#
# The corpus is baked at /data/corpus (NOT /test/corpus) on purpose: `--precision`
# applies a test-path penalty to credentials under a `test/`-component path, which
# would legitimately drop the planted key below the high-precision floor and make
# `precision/aws-found` a false failure. A neutral `/data` path keeps the "found
# under every profile" invariant true. (The Dockerfiles document the same.)
CLI_PROFILES=(
  "default|"
  "fast|--fast"
  "deep|--deep"
  "precision|--precision"
  "no-entropy|--no-entropy"
  "no-ml|--no-ml"
  "no-gpu|--no-gpu"
  "backend-cpu|--backend cpu"
  "backend-simd|--backend simd"
  "threads-1|--threads 1"
)
# name | scan args after profile | want_exit | grep | forbid
INVARIANTS=(
  "aws-found|--format json /data/corpus/aws_leak.env|1|aws-access-key|-"
  "clean-clean|--format json /data/corpus/clean.txt|0|[]|detector_id"
  "fp-trap-clean|--format json /data/corpus/fp_trap.txt|0|[]|detector_id"
)
for prof in "${CLI_PROFILES[@]}"; do
  IFS='|' read -r pname pflags <<<"$prof"
  if [[ "$pname" == "backend-simd" && "$HAS_SIMD" == 0 ]]; then continue; fi
  for inv in "${INVARIANTS[@]}"; do
    IFS='|' read -r iname iargs ix ig if_ <<<"$inv"
    check "inv:$pname/$iname" "-" "scan $pflags $iargs" "$ix" "$ig" "$if_"
  done
done

# --- Layer 2: per-surface checks (run once, default env) --------------------
# name | env | args | want_exit | grep | forbid
SURFACES=(
  "scan-text|-|scan --format text /data/corpus/aws_leak.env|1|AWS Access Key|-"
  "scan-jsonl|-|scan --format jsonl /data/corpus/aws_leak.env|1|aws-access-key|-"
  "scan-sarif|-|scan --format sarif /data/corpus/aws_leak.env|1|2.1.0|-"
  "scan-dir|-|scan --format json /data/corpus|1|aws-access-key|-"
  "scan-min-confidence|-|scan --min-confidence 0.0 --format json /data/corpus/aws_leak.env|1|aws-access-key|-"
  "scan-backend-simd|-|scan --backend simd --format json /data/corpus/aws_leak.env|1|aws-access-key|-"
  "scan-no-gpu|-|scan --no-gpu --format json /data/corpus/aws_leak.env|1|aws-access-key|-"
  "scan-threads-1|-|scan --threads 1 --format json /data/corpus/aws_leak.env|1|aws-access-key|-"
  "scan-threads-64|-|scan --threads 64 --format json /data/corpus/aws_leak.env|1|aws-access-key|-"
  "require-gpu-fails-closed|-|scan --require-gpu /data/corpus/aws_leak.env|12|-|-"
  "doctor-self-test|-|doctor|0|PASS|-"
  "detectors-count|-|detectors|0|Loaded |-"
  "explain-detector|-|explain aws-access-key|0|AWS Access Key|-"
  "completion-bash|-|completion bash|0|_keyhog|-"
  "completion-zsh|-|completion zsh|0|#compdef|-"
  "completion-fish|-|completion fish|0|keyhog|-"
  "backend-inspect|-|backend|0|hardware|-"
  "calibrate-noop|-|calibrate|0|detector counters|-"
  "hook-help-exit2|-|hook|2|install|-"
  "version|-|--version|0|KeyHog v|-"
  "help|-|--help|0|secret|-"
  "missing-path-exit2|-|scan /data/corpus/nope.env|2|-|detector_id"
  "empty-dir-clean|-|scan /tmp|0|-|-"
)
for s in "${SURFACES[@]}"; do
  IFS='|' read -r n e a x g f <<<"$s"
  if [[ "$n" == "scan-backend-simd" && "$HAS_SIMD" == 0 ]]; then continue; fi
  check "surf:$n" "$e" "$a" "$x" "$g" "$f"
done

# --- Special cases that need stdin / read-only / escape handling ------------

# stdin scan (--stdin reads fd 0, not a path arg). Feed the BAKED corpus file
# into stdin in-container: this is byte-identical to the image's calibration
# (`calib --stdin < /data/corpus/aws_leak.env`), so the autoroute stdin workload
# bucket matches and the scan resolves a decision instead of failing closed. The
# bucket is content-sensitive, so a pipe of different bytes would miss it; keyhog
# reads fd 0 regardless of pipe-vs-redirect, so this still exercises --stdin.
out="$(docker run --rm "$IMAGE" \
  sh -c 'keyhog scan --stdin --format json < /data/corpus/aws_leak.env' 2>&1)"
if [[ $? == 1 ]] && grep -qF aws-access-key <<<"$out"; then
  PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); FAILED+=("special:stdin-scan"); echo "  ✗ [special:stdin-scan]"; fi

# read-only root filesystem: a scan must still work (no scratch writes needed).
out="$(docker run --rm --read-only "$IMAGE" keyhog scan --format json /data/corpus/aws_leak.env 2>&1)"
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

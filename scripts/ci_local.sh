#!/usr/bin/env bash
# Local CI level (Full workspace validation including GPU hardware test battery).
# Runs full test matrix with GPU/CUDA/WGPU acceleration enabled on local GPU hardware.
set -euo pipefail
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== [Local CI] 1. Remote CI Battery (Base Suite) ==="
bash scripts/ci_remote.sh

echo "=== [Local CI] 2. Scanner Default / GPU Test Suite ==="
cargo test -p keyhog-scanner --features gpu --test all_tests --profile ci-test -- --test-threads=16

echo "=== [Local CI] 3. GPU Hardware Parity & Dispatch Contracts ==="
cargo test -p keyhog-scanner --features gpu --profile release-fast \
  --test gpu_parity \
  --test gpu_ac_smoke \
  --test gpu_ac_recall_bug_56 \
  --test gpu_proptest_invariants \
  --test gpu_region_overfire_validation \
  --test gpu_entropy_recall_parity \
  --test gpu_peer_backend_parity \
  --test gpu_resident_output_ownership \
  --test regression_gpu_region_presence_batch_parity \
  --test packed_gpu_vyre_artifact \
  --test gpu_literal_artifact_writer

echo "=== [Local CI] 4. GPU CLI Integration & Error Handling ==="
cargo test -p keyhog --features gpu,simd --profile ci-test \
  --test regression_require_gpu_fails_closed \
  --test e2e_gpu_autoroute_optin \
  --test gpu_simd_parity

echo "=== [Local CI] ALL CHECKS PASSED (Local CI Level with GPU) ==="

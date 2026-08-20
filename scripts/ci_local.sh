#!/usr/bin/env bash
# Local CI level (Full workspace validation including GPU hardware test battery).
# Runs full test matrix with GPU/CUDA/WGPU acceleration enabled on local GPU hardware.
#
# This lane is the ONLY place GPU finding parity is proved. Hosted PR CI has no
# adapter and never will, so it runs the hardware-free wiring contract instead
# (`scripts/gates/gpu_wired.py` and `--test gpu_wiring_contract`).
#
# KEYHOG_REQUIRE_GPU arms the require-GPU runtime policy for the test support
# gate. Without it `require_gpu_or_panic` returns at its first line, every GPU
# parity assertion is skipped, and a runner whose driver died still reports a
# green GPU suite. The preflight below fails the lane before any test runs when
# no adapter can execute region presence.
set -euo pipefail
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export KEYHOG_REQUIRE_GPU=1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== [Local CI] 1. Workspace check ==="
cargo check --workspace --all-targets -j "${CARGO_BUILD_JOBS:-1}"

echo "=== [Local CI] 1b. GPU hardware preflight (fails closed with no adapter) ==="
cargo run -j "${CARGO_BUILD_JOBS:-1}" -p keyhog --features gpu,simd --profile release-fast -- \
  backend --self-test --require-gpu

echo "=== [Local CI] 1c. GPU wiring contract ==="
cargo test -j "${CARGO_BUILD_JOBS:-1}" -p keyhog-scanner --features gpu --profile ci-test \
  --test gpu_wiring_contract

echo "=== [Local CI] 2. Scanner Default / GPU Test Suite ==="
cargo test -j "${CARGO_BUILD_JOBS:-1}" -p keyhog-scanner --features gpu --test all_tests --profile ci-test -- --test-threads=16

echo "=== [Local CI] 3. GPU Hardware Parity & Dispatch Contracts ==="
cargo test -j "${CARGO_BUILD_JOBS:-1}" -p keyhog-scanner --features gpu --profile release-fast \
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
  --test gpu_literal_artifact_writer \
  --test regression_row_103_gpu_upload_readback_latency

echo "=== [Local CI] 4. GPU CLI Integration & Error Handling ==="
cargo test -j "${CARGO_BUILD_JOBS:-1}" -p keyhog --features gpu,simd --profile ci-test \
  --test regression_require_gpu_fails_closed \
  --test e2e_gpu_autoroute_optin \
  --test gpu_simd_parity

echo "=== [Local CI] ALL CHECKS PASSED (Local CI Level with GPU) ==="

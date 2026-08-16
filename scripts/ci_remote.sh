#!/usr/bin/env bash
# Remote CI level (CPU-only, non-GPU, exact CI workflow parity).
# Runs the full headless test battery used by GitHub Actions.
set -euo pipefail
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-16}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== [Remote CI] 1. Formatting & Gate Checks ==="
cargo fmt -p keyhog-core -p keyhog-profile -p keyhog-scanner -p keyhog -p keyhog-verifier -p keyhog-sources -- --check
python3 -B scripts/gates/complexity_budget.py
python3 -B scripts/gates/crate_changelogs.py --allow-released \
  crates/cli/CHANGELOG.md crates/core/CHANGELOG.md crates/scanner/CHANGELOG.md \
  crates/sources/CHANGELOG.md crates/verifier/CHANGELOG.md
python3 -B scripts/gates/action_docs_contract.py
python3 -B scripts/gates/workflow_docs_boundaries.py
python3 -B scripts/gates/docs_truth.py

echo "=== [Remote CI] 2. Fast Build & Smoke Test ==="
cargo build --profile release-fast -p keyhog --features simd

echo "=== [Remote CI] 3. Core & Verifier Test Suites ==="
cargo test -p keyhog-core --test all_tests --profile ci-test -- --test-threads=16
cargo test -p keyhog-core --test new_core_finding_dedup --profile ci-test
cargo test -p keyhog-verifier --test all_tests --profile ci-test
cargo test -p keyhog-verifier --test break_it --profile ci-test -- --test-threads=1
cargo test -p keyhog-verifier --lib

echo "=== [Remote CI] 4. Scanner Lean Test Suite (Non-GPU) ==="
cargo test -p keyhog-scanner --test all_tests --no-default-features --features ci-lean --profile ci-test -- --test-threads=16
cargo test -p keyhog-scanner --test decode_coalesced_sparse_parity --no-default-features --features ci-lean --profile ci-test
cargo test -p keyhog-scanner --test execution_pack_lazy_mapping --no-default-features --features ci-lean --profile ci-test
cargo test -p keyhog-scanner --test perf_alloc_batch_topology --no-default-features --features ci-lean --profile ci-test
cargo test -p keyhog-scanner --test perf_alloc_trigger_scratch --no-default-features --features ci-lean --profile ci-test
cargo test -p keyhog-scanner --test adversarial_suite --no-default-features --features ci-lean --profile ci-test
cargo test -p keyhog-scanner --test all_detectors_self_validate --profile ci-test
cargo test -p keyhog-scanner --lib --no-default-features --features ci-lean -- --test-threads=16

echo "=== [Remote CI] 5. CLI & Profile Test Suites ==="
cargo test -p keyhog-profile
cargo test -p keyhog --lib
cargo test -p keyhog --test all_tests --no-default-features --features ci-lean --profile ci-test -- --test-threads=16
cargo test -p keyhog --test e2e_binary --profile ci-test
cargo test -p keyhog --test sarif_github_compliance --profile ci-test
cargo test -p keyhog --test vyre_pin_coherence_lane3 --no-default-features --features ci-lean --profile ci-test
cargo test -p keyhog --no-default-features --features ci-lean --profile ci-test \
  --test coherence_wiring_lane7 --test lane10_verification_doc_coherence --test coherence_verify_count

echo "=== [Remote CI] 6. Sources Test Suite ==="
cargo test -p keyhog-sources --features "github,gitlab,bitbucket,slack,azure,gcs,s3,docker,binary" --profile ci-test -- --test-threads=1

echo "=== [Remote CI] 7. Documentation Coherence ==="
make docs-check

echo "=== [Remote CI] ALL CHECKS PASSED (Remote CI Level) ==="

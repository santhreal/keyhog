//! KH-GAP-003: When the GPU runtime policy requires a GPU, GPU gates must
//! panic/fail instead of returning early with an implicit skip.
//!
//! GPU-feature-gated, mirroring `tests/integration/gpu.rs` and
//! `tests/gap/selected_gpu_backend_executes_or_fails.rs`: the require-GPU gate
//! only has meaning when the GPU stack is compiled in. Under the lean `ci-lean`
//! aggregator (`--no-default-features --features ci-lean`, no `gpu`)
//! `gpu_available()` is a const-false stub, so this test would panic on a
//! GPU-less host without exercising a compiled GPU path.
#![cfg(feature = "gpu")]

use keyhog_scanner::gpu::GpuRuntimePolicy;
use keyhog_scanner::testing::require_gpu_preflight_with_policy_for_test;

#[test]
fn gpu_require_policy_fails_not_skips() {
    if let Err(error) = require_gpu_preflight_with_policy_for_test(GpuRuntimePolicy::Required) {
        panic!(
            "Fix: --require-gpu requested but no compatible GPU adapter - \
             fail loudly with probe detail instead of skipping GPU gates: {error}"
        );
    }
}

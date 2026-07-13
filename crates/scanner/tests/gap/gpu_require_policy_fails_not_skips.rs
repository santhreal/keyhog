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

use keyhog_scanner::gpu::{
    gpu_available, gpu_runtime_policy, set_gpu_runtime_policy, GpuRuntimePolicy,
};

fn gpu_required_gate() {
    if keyhog_scanner::gpu::gpu_runtime_policy() != GpuRuntimePolicy::Required {
        return;
    }

    if !gpu_available() {
        panic!(
            "Fix: --require-gpu requested but no compatible GPU adapter - \
             fail loudly with probe detail instead of skipping GPU gates"
        );
    }
}

struct GpuPolicyGuard(GpuRuntimePolicy);

impl GpuPolicyGuard {
    fn set(policy: GpuRuntimePolicy) -> Self {
        let prior = gpu_runtime_policy();
        set_gpu_runtime_policy(policy);
        Self(prior)
    }
}

impl Drop for GpuPolicyGuard {
    fn drop(&mut self) {
        set_gpu_runtime_policy(self.0);
    }
}

#[test]
fn gpu_require_policy_fails_not_skips() {
    let _policy = GpuPolicyGuard::set(GpuRuntimePolicy::Required);
    gpu_required_gate();
}

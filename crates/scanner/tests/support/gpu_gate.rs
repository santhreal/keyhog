//! Hard-fail gate when GPU validation is mandatory.
//!
//! The gate reads the process-global GPU runtime policy, which defaults to
//! `Auto`. Nothing in the library sets it from the environment, so before
//! `arm_policy_from_env` existed every CI lane ran with `Auto` and this gate
//! returned at its first line. Measured consequence: `gpu_parity`,
//! `gpu_ac_smoke` and `gpu_peer_backend_parity` reported 12 passed and
//! 0 ignored on a host with no adapter, because every assertion behind this
//! gate was skipped and the suite called that success.
//!
//! `KEYHOG_REQUIRE_GPU=1` is a test-lane arming switch, not a product surface:
//! the shipped binary reaches `Required` through `--require-gpu`, an explicit
//! GPU `--backend`, or `[system]` config. `scripts/ci_local.sh` sets it so the
//! self-hosted release lane cannot pass without a working adapter, and
//! `scripts/gates/gpu_wired.py` fails CI if that lane stops setting it.

use std::sync::Once;

static ARM: Once = Once::new();

/// Promote the runtime policy to `Required` when the release lane asks for it.
///
/// Idempotent and safe to call from every gated test; the first caller wins and
/// an already-required policy is left alone.
pub fn arm_policy_from_env() {
    ARM.call_once(|| {
        let requested = std::env::var("KEYHOG_REQUIRE_GPU").is_ok_and(|v| v == "1");
        if requested && !keyhog_scanner::gpu::gpu_required_by_policy() {
            keyhog_scanner::gpu::set_gpu_runtime_policy(
                keyhog_scanner::gpu::GpuRuntimePolicy::Required,
            );
        }
    });
}

/// When the explicit GPU runtime policy requires a GPU, panic if no compatible
/// adapter is present.
pub fn require_gpu_or_panic(context: &str) {
    arm_policy_from_env();
    if !keyhog_scanner::gpu::gpu_required_by_policy() {
        return;
    }
    if !keyhog_scanner::gpu::gpu_available() {
        panic!(
            "{context}: --require-gpu requested but no compatible GPU adapter - \
             fail loudly instead of skipping GPU gates"
        );
    }
}

/// Hard-fail when GPU scan returned zero findings but a reference backend found matches.
pub fn assert_gpu_not_silent_empty(gpu_empty: bool, reference_finding_count: usize, context: &str) {
    if gpu_empty && reference_finding_count > 0 {
        panic!(
            "{context}: GPU returned zero findings vs {reference_finding_count} reference findings - \
             adapter init failure or silent CPU fallback must fail loudly, not skip"
        );
    }
}

//! KH-GAP-003: When `KEYHOG_REQUIRE_GPU=1`, GPU gates must panic/fail
//! - never return early with an implicit skip.
//!
//! GPU-feature-gated, mirroring `tests/integration/gpu.rs` and
//! `tests/gap/gpu_forced_backend_no_silent_degrade.rs`: the require-GPU gate
//! only has meaning when the GPU stack is compiled in. Under the lean `ci-lean`
//! aggregator (`--no-default-features --features ci-lean`, no `gpu`)
//! `gpu_available()` is a const-false stub, so this test panics on a GPU-less
//! host - AND, panicking BEFORE its `remove_var`, LEAKS `KEYHOG_REQUIRE_GPU=1`
//! into the process env. A concurrent scan in the parallel `all_tests` pool then
//! reads that forced value and `gpu_forced` process-exits, aborting the whole
//! binary before it can report. Gating keeps this on the `gpu` build
//! (runners-nightly, real GPU hosts) that can actually exercise the path.
#![cfg(feature = "gpu")]

use keyhog_scanner::gpu::gpu_available;

fn gpu_required_gate() {
    let require = std::env::var("KEYHOG_REQUIRE_GPU").ok();
    let strict = matches!(require.as_deref(), Some("1") | Some("true") | Some("yes"));
    if !strict {
        return;
    }

    if !gpu_available() {
        panic!(
            "Fix: KEYHOG_REQUIRE_GPU=1 but no compatible GPU adapter - \
             fail loudly with probe detail instead of skipping GPU gates"
        );
    }
}

#[test]
fn gpu_require_env_fails_not_skips() {
    unsafe { std::env::set_var("KEYHOG_REQUIRE_GPU", "1") };
    gpu_required_gate();
    unsafe { std::env::remove_var("KEYHOG_REQUIRE_GPU") };
}

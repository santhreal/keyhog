//! Hardware-free GPU wiring contract. Runs on a hosted runner with no adapter.
//!
//! WHY THIS FILE EXISTS
//!
//! `cargo test -p keyhog-scanner --test gpu_parity --test gpu_ac_smoke
//! --test gpu_peer_backend_parity`, built WITHOUT `--features gpu` on a host
//! with no adapter policy, reported `4 passed`, `2 passed`, `6 passed`,
//! `0 ignored`. Twelve GPU tests, all green, none of which touched a GPU.
//!
//! The cause is not a missing runner. Every hard-fail assertion in those files
//! goes through `support::gpu_gate::require_gpu_or_panic`, which returns
//! immediately unless `gpu_required_by_policy()` is true. The policy defaults to
//! `Auto` and no lane armed it, not the hosted lane and not the self-hosted
//! release lane, so the guard was inert everywhere. A CI-green GPU suite was
//! reporting the absence of a GPU as success.
//!
//! This file is the lane that cannot pass vacuously. It needs no adapter, so it
//! belongs on hosted PR CI, and it goes red when the GPU path is unwired:
//!
//!   1. the target was built without `--features gpu`
//!   2. the require-GPU arming mechanism the release lane depends on is gone
//!   3. a GPU backend override exists that does not round-trip through
//!      `parse_backend_str`, or is not reported as a GPU route
//!   4. the require-GPU preflight stops failing closed on an adapter-free host
//!
//! WHAT IT DOES NOT CATCH: whether a real adapter produces correct findings.
//! Finding parity needs hardware and belongs to the self-hosted release lane in
//! `scripts/ci_local.sh`, which arms the policy and runs a
//! `keyhog backend --self-test` preflight before any GPU test executes.

mod support;
use support::gpu_gate::require_gpu_or_panic;

use std::sync::{Mutex, MutexGuard};

use keyhog_scanner::gpu::{
    gpu_available, gpu_required_by_policy, gpu_runtime_policy, set_gpu_runtime_policy,
    GpuRuntimePolicy,
};
use keyhog_scanner::hw_probe::{parse_backend_str, BACKEND_OVERRIDE_VALUES};
use keyhog_scanner::testing::require_gpu_preflight_with_policy_for_test;

/// The runtime policy is process-global, so the tests that move it serialize and
/// restore it. Without this a parallel test observes another test's policy.
static POLICY_LOCK: Mutex<()> = Mutex::new(());

struct PolicyGuard {
    _lock: MutexGuard<'static, ()>,
    previous: GpuRuntimePolicy,
}

impl PolicyGuard {
    fn set(policy: GpuRuntimePolicy) -> Self {
        let lock = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = gpu_runtime_policy();
        set_gpu_runtime_policy(policy);
        Self {
            _lock: lock,
            previous,
        }
    }
}

impl Drop for PolicyGuard {
    fn drop(&mut self) {
        set_gpu_runtime_policy(self.previous);
    }
}

/// The one assertion the twelve vacuous tests were missing.
///
/// A lane that forgets `--features gpu` compiles this target, runs it, and fails
/// here instead of reporting green GPU coverage it never had.
#[test]
fn target_is_built_with_the_gpu_feature() {
    assert!(
        cfg!(feature = "gpu"),
        "gpu_wiring_contract must be built with --features gpu. Without the \
         feature the GPU adapter branch in gpu::gpu_probe is not compiled, every \
         GPU test in this crate degrades to a CPU run, and the suite reports \
         green GPU coverage that does not exist. Run this target as: \
         cargo test -p keyhog-scanner --features gpu --test gpu_wiring_contract"
    );
}

/// Every GPU route an operator can request must survive the round trip from CLI
/// string to `ScanBackend` and back to its label.
///
/// The variant space is derived at run time from `BACKEND_OVERRIDE_VALUES`, so a
/// GPU override added without routing support fails here rather than at the
/// first operator who types it.
#[test]
fn every_gpu_backend_override_round_trips() {
    let mut gpu_overrides = 0usize;
    for raw in BACKEND_OVERRIDE_VALUES {
        let Some(backend) = parse_backend_str(raw) else {
            assert_eq!(
                raw, "auto",
                "{raw} is an advertised backend override but parse_backend_str \
                 does not resolve it; only `auto` may be unresolvable"
            );
            continue;
        };
        if !backend.is_gpu() {
            continue;
        }
        gpu_overrides += 1;
        let label = backend.label();
        assert!(
            !label.is_empty(),
            "{raw} resolves to a GPU backend with an empty label"
        );
        assert_eq!(
            parse_backend_str(label),
            Some(backend),
            "{raw} resolves to {backend:?} whose own label {label} does not \
             parse back to it; autoroute evidence stores these labels, so a \
             one-way label silently invalidates a persisted decision"
        );
    }
    assert!(
        gpu_overrides > 0,
        "no GPU backend override survives parse_backend_str. The GPU routes \
         were removed or renamed and this crate no longer offers a GPU path, \
         which the product claims to have"
    );
}

/// The release lane depends on being able to demand a GPU. If arming stops
/// working, every hard-fail GPU gate silently disarms again, which is the exact
/// regression this file exists for.
#[test]
fn require_gpu_policy_can_be_armed_and_restored() {
    let baseline = {
        let _guard = PolicyGuard::set(GpuRuntimePolicy::Auto);
        gpu_required_by_policy()
    };
    assert!(
        !baseline,
        "the Auto policy must not report a required GPU; if it does, the \
         require-GPU contract no longer distinguishes demanded from optional"
    );

    let armed = {
        let _guard = PolicyGuard::set(GpuRuntimePolicy::Required);
        gpu_required_by_policy()
    };
    assert!(
        armed,
        "set_gpu_runtime_policy(Required) did not arm gpu_required_by_policy. \
         Every GPU hard-fail gate reads this predicate, so an unarmable policy \
         turns the whole GPU suite into a no-op"
    );

    assert!(
        !gpu_required_by_policy(),
        "the policy guard did not restore the previous policy, which leaks a \
         required-GPU state into unrelated tests"
    );
}

/// On an adapter-free host, demanding a GPU must fail closed with an actionable
/// message. On a real GPU host the same call must succeed. Both directions are
/// asserted so this test is meaningful in the hosted lane and in the release
/// lane without being conditional on which one is running.
#[test]
fn require_gpu_preflight_matches_adapter_reality() {
    let _guard = PolicyGuard::set(GpuRuntimePolicy::Auto);
    let adapter_present = gpu_available();
    let outcome = require_gpu_preflight_with_policy_for_test(GpuRuntimePolicy::Required);

    if adapter_present {
        assert!(
            outcome.is_ok(),
            "a usable adapter is present but the require-GPU preflight refused \
             to run: {outcome:?}. A working GPU host must not be rejected"
        );
        return;
    }

    let diagnostic = outcome.expect_err(
        "no usable GPU adapter is present, so the require-GPU preflight must \
         fail closed. Returning Ok here is the silent CPU substitution the \
         require-GPU contract forbids, and it is what lets a release ship from \
         a runner whose driver died",
    );
    for fragment in [
        "GPU execution is required by the resolved runtime policy",
        "refusing to run on CPU",
        "--require-gpu",
    ] {
        assert!(
            diagnostic.contains(fragment),
            "the require-GPU diagnostic must name the condition and the way out; \
             missing {fragment:?} in: {diagnostic}"
        );
    }
}

/// The Auto policy must never be treated as a demand. This pins the direction of
/// the default so a future change that makes `Auto` behave as `Required` is
/// caught here rather than by an operator whose CPU-only box stops scanning.
#[test]
fn auto_policy_does_not_demand_a_gpu() {
    let _guard = PolicyGuard::set(GpuRuntimePolicy::Auto);
    assert!(
        require_gpu_preflight_with_policy_for_test(GpuRuntimePolicy::Auto).is_ok(),
        "the Auto policy must never fail closed on a missing GPU"
    );
    assert!(
        require_gpu_preflight_with_policy_for_test(GpuRuntimePolicy::Disabled).is_ok(),
        "the Disabled policy must never fail closed on a missing GPU"
    );
}
#[test]
fn require_gpu_or_panic_panics_on_unmet_policy() {
    let _guard = PolicyGuard::set(GpuRuntimePolicy::Auto);
    // When policy is Auto, require_gpu_or_panic does not panic
    require_gpu_or_panic("test_auto");

    // When policy is Required and preflight fails (H0/H1/H3), require_gpu_or_panic must panic
    let preflight = require_gpu_preflight_with_policy_for_test(GpuRuntimePolicy::Required);
    if preflight.is_err() {
        let _required_guard = PolicyGuard::set(GpuRuntimePolicy::Required);
        let result = std::panic::catch_unwind(|| {
            require_gpu_or_panic("test_required_fault");
        });
        assert!(
            result.is_err(),
            "require_gpu_or_panic must panic when require_gpu_preflight fails on Required policy"
        );
    }
}

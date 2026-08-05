//! The require-GPU preflight proves region-presence parity and says so usefully.
//!
//! Two different things are pinned, and only one of them can be read from
//! source. Which self-test the preflight calls is an architectural choice:
//! `gpu_self_test` proves an adapter exists, `gpu_region_presence_self_test`
//! proves the production trigger path agrees with the scalar reference, and
//! quietly swapping to the weaker one would let a GPU that finds the wrong
//! things satisfy `--require-gpu`. That is a call-graph property, so it is
//! checked in source.
//!
//! What the operator is told is behaviour, and it used to be checked in source
//! too, by grepping for message fragments. That broke the moment the message
//! was rewrapped, while the message itself was fine, and it would equally have
//! passed on a message that read correctly in source and never reached anyone.
//! It now calls the preflight and reads what comes back.

use keyhog_scanner::gpu::GpuRuntimePolicy;
use keyhog_scanner::testing::require_gpu_preflight_with_policy_for_test;

/// A preflight that is not required never blocks a scan.
#[test]
fn a_non_required_policy_passes_preflight() {
    assert!(require_gpu_preflight_with_policy_for_test(GpuRuntimePolicy::Auto).is_ok());
    assert!(require_gpu_preflight_with_policy_for_test(GpuRuntimePolicy::Disabled).is_ok());
}

/// When the preflight refuses, it names the condition and every way out of it.
///
/// The policy reaches `Required` through `--require-gpu` OR an explicit GPU
/// `--backend`, and the refusal used to name only the flag. An operator who
/// wrote `--backend gpu-cuda` was told to "run without --require-gpu", a flag
/// they never passed.
///
/// A host with a working GPU returns `Ok`, which is the other correct outcome,
/// so the message is only asserted when there is one.
#[test]
fn a_refusal_names_the_condition_and_both_ways_out() {
    let Err(message) = require_gpu_preflight_with_policy_for_test(GpuRuntimePolicy::Required)
    else {
        return;
    };

    assert!(
        message.contains("required by the resolved runtime policy"),
        "the refusal must name the policy, not one of the flags that can set it: {message}"
    );
    assert!(
        message.contains("--require-gpu") && message.contains("--backend gpu-cuda"),
        "both routes into the required policy must be named: {message}"
    );
    assert!(
        message.contains("drop --require-gpu and any explicit GPU --backend"),
        "the operator must be told every way to leave the required policy: {message}"
    );
    assert!(
        message.contains("refusing to run on CPU"),
        "the refusal must be explicit that no CPU fallback happened: {message}"
    );
}

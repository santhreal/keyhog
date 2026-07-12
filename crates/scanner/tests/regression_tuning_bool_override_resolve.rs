//! Contract for the `ScannerTuningConfig` boolean-override resolution
//! (`tuning::BoolOverride`), the Tier-A knob mechanism behind the runtime
//! phase-2/decode/GPU tuning flags. Previously untested directly.
//!
//! Each flag is a 3-state atomic override resolved against a compiled default:
//! an UNSET override (`None`) resolves to the flag's compiled default, a forced
//! `Some(true)`/`Some(false)` overrides it. A bug in `resolve()` / `from_option`
//! would silently ignore an operator's `--tune`/env override or flip a default —
//! a Tier-A wiring failure (Review Vector 9: a parsed override must reach
//! operator-visible behavior). These round-trip the real setter+getter on a
//! fresh local config, so the assertions are deterministic and env-independent.

use keyhog_scanner::testing::{
    tuning_phase2_localizer_roundtrip_for_test as localizer, TUNING_LOCALIZER_DEFAULT,
};
// The GPU recall-floor roundtrip helper exercises `gpu_recall_floor_enabled`,
// a `#[cfg(feature = "gpu")]` reader (the recall floor is a GPU-region-presence
// knob), so the helper compiles only under `gpu`. Import + assert it under the
// same gate; the localizer half of every test below stays feature-independent.
#[cfg(feature = "gpu")]
use keyhog_scanner::testing::{
    tuning_gpu_recall_floor_roundtrip_for_test as gpu_floor, TUNING_GPU_RECALL_FLOOR_DEFAULT,
};

#[test]
fn force_on_override_resolves_true() {
    assert!(localizer(Some(true)), "ForceOn must resolve to true");
    #[cfg(feature = "gpu")]
    assert!(gpu_floor(Some(true)), "ForceOn must resolve to true");
}

#[test]
fn force_off_override_resolves_false() {
    assert!(!localizer(Some(false)), "ForceOff must resolve to false");
    #[cfg(feature = "gpu")]
    assert!(!gpu_floor(Some(false)), "ForceOff must resolve to false");
}

#[test]
fn unset_override_resolves_to_the_compiled_default() {
    assert_eq!(
        localizer(None),
        TUNING_LOCALIZER_DEFAULT,
        "an unset override must resolve to the compiled localizer default"
    );
    #[cfg(feature = "gpu")]
    assert_eq!(
        gpu_floor(None),
        TUNING_GPU_RECALL_FLOOR_DEFAULT,
        "an unset override must resolve to the compiled gpu-recall-floor default"
    );
}

#[test]
fn force_on_and_force_off_are_distinct_resolutions() {
    // resolve() actually distinguishes the two forced states (not a constant).
    assert_ne!(localizer(Some(true)), localizer(Some(false)));
    #[cfg(feature = "gpu")]
    assert_ne!(gpu_floor(Some(true)), gpu_floor(Some(false)));
}

#[test]
fn a_forced_override_wins_over_the_default_when_they_differ() {
    // Forcing the OPPOSITE of the default must actually change the resolved value
    // — proves the override takes precedence over the compiled default.
    assert_eq!(
        localizer(Some(!TUNING_LOCALIZER_DEFAULT)),
        !TUNING_LOCALIZER_DEFAULT
    );
    #[cfg(feature = "gpu")]
    assert_eq!(
        gpu_floor(Some(!TUNING_GPU_RECALL_FLOOR_DEFAULT)),
        !TUNING_GPU_RECALL_FLOOR_DEFAULT
    );
}

//! Unit tests for `subcommands::backend`. Split into a separate `tests.rs`
//! module (rather than an inline `#[cfg(test)] mod tests {}` block) so the
//! `no_inline_tests_in_src` gate stays green while these still reach the parent
//! module's classification predicates via `use super::*`.

use super::*;

#[test]
fn tier_b_gpu_lowering_gap_data_drives_classification() {
    // The Tier-B `rules/gpu-lowering-gaps.toml` set must (a) load and be
    // non-empty (fail-closed contract: an empty set would misclassify every GPU
    // error as a hard FAIL) and (b) actually WIRE into the classifier, every
    // configured marker, embedded mid-string, must classify as a KNOWN
    // limitation. This replaces the old tautology (`ARRAY == same ARRAY`) with a
    // real behavioral assertion over the loaded data.
    let rules = &*GPU_LOWERING_GAP_RULES;
    assert!(
        !rules.lowering_gap_markers.is_empty(),
        "lowering_gap_markers must be non-empty"
    );
    assert!(
        !rules.moe_parity_degrade_markers.is_empty(),
        "moe_parity_degrade_markers must be non-empty"
    );

    // Every loaded lowering-gap marker classifies a realistic error string.
    for marker in &rules.lowering_gap_markers {
        let error = format!("GPU self-test failed: {marker} was referenced before binding");
        assert!(
            is_known_vyre_lowering_gap(&error),
            "loaded marker {marker:?} must classify its error as a known lowering gap"
        );
        // ... and is NOT mistaken for the orthogonal MoE-parity class.
        assert!(!is_moe_parity_degrade(&error));
    }
    for marker in &rules.moe_parity_degrade_markers {
        let error = format!("GPU MoE compute shader {marker} by 0.0123");
        assert!(
            is_moe_parity_degrade(&error),
            "loaded marker {marker:?} must classify its error as a MoE parity degrade"
        );
        assert!(!is_known_vyre_lowering_gap(&error));
    }

    // The three canonical vyre lowering-gap substrings + the MoE marker ship in
    // the bundled data (pins the shipped set without pinning ORDER or COUNT).
    for expected in [
        "_vyre_match_leader",
        "canonical pre-emit lowering",
        "subgroup_ballot",
    ] {
        assert!(
            rules.lowering_gap_markers.iter().any(|m| m == expected),
            "bundled data must ship the canonical marker {expected:?}"
        );
    }
    assert!(rules
        .moe_parity_degrade_markers
        .iter()
        .any(|m| m == "diverges from the CPU MoE reference"));
}

#[test]
fn is_known_vyre_lowering_gap_matches_each_marker() {
    assert!(is_known_vyre_lowering_gap(
        "_vyre_match_leader is referenced before binding"
    ));
    assert!(is_known_vyre_lowering_gap(
        "the canonical pre-emit lowering rejected the literal set"
    ));
    assert!(is_known_vyre_lowering_gap(
        "shader uses subgroup_ballot which is unsupported"
    ));
    // A genuine GPU-unavailable / dispatch failure is NOT a known gap.
    assert!(!is_known_vyre_lowering_gap(
        "GPU adapter lost during dispatch"
    ));
    assert!(!is_known_vyre_lowering_gap(""));
}

#[test]
fn is_moe_parity_degrade_matches_only_the_parity_marker() {
    assert!(is_moe_parity_degrade(
        "GPU MoE compute shader diverges from the CPU MoE reference by 0.0123"
    ));
    assert!(!is_moe_parity_degrade(
        "GPU MoE dispatch failed: device lost"
    ));
    assert!(!is_moe_parity_degrade(""));
}

#[test]
fn require_gpu_turns_adapter_absence_into_a_failed_health_report() {
    let caps = HardwareCaps {
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: true,
        has_avx512: false,
        has_neon: false,
        gpu_available: false,
        gpu_name: None,
        gpu_vram_mb: None,
        gpu_runtime_identity: None,
        gpu_is_software: false,
        total_memory_mb: Some(32 * 1024),
        io_uring_available: true,
        hyperscan_available: true,
    };

    let optional = unavailable_gpu_self_test_report(&caps, false);
    assert!(optional.ok);
    assert_eq!(optional.status, BackendSelfTestStatus::Skip);
    assert_eq!(optional.exit_code, EXIT_SUCCESS);
    assert_eq!(optional.probes[0].status, BackendSelfTestStatus::Skip);

    let required = unavailable_gpu_self_test_report(&caps, true);
    assert!(!required.ok);
    assert_eq!(required.status, BackendSelfTestStatus::Fail);
    assert_eq!(required.exit_code, EXIT_BACKEND_SELF_TEST_FAILED);
    assert_eq!(required.probes[0].name, "gpu_adapter");
    assert_eq!(required.probes[0].status, BackendSelfTestStatus::Fail);
    assert!(required.probes[0]
        .message
        .as_deref()
        .is_some_and(|message| message.contains("--require-gpu requested")));
}

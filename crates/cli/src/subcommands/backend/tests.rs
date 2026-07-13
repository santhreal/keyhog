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

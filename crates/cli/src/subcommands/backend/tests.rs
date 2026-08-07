//! Unit tests for `subcommands::backend`. Split into a separate `tests.rs`
//! module (rather than an inline `#[cfg(test)] mod tests {}` block) so the
//! `no_inline_tests_in_src` gate stays green while these still reach the parent
//! module's classification predicates via `use super::*`.

use super::*;
// The self-test report types and the two exit codes it names moved to
// `backend/self_test.rs` when the subcommand split by responsibility, and the
// hardware capability struct comes from the scanner probe rather than from the
// parent module's import list. Name them here instead of relying on whatever
// `backend.rs` happens to import.
use crate::exit_codes::{EXIT_BACKEND_SELF_TEST_FAILED, EXIT_SUCCESS};
use keyhog_scanner::hw_probe::HardwareCaps;

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

    // Every loaded lowering-gap marker classifies a realistic error string.
    for marker in &rules.lowering_gap_markers {
        let error = format!("GPU self-test failed: {marker} was referenced before binding");
        assert!(
            is_known_vyre_lowering_gap(&error),
            "loaded marker {marker:?} must classify its error as a known lowering gap"
        );
    }

    // The three canonical VYRE lowering-gap substrings ship in the bundled
    // data (pins the shipped set without pinning order or count).
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
        hyperscan_runtime_identity: None,
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

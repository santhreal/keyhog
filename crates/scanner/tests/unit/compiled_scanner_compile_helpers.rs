use super::*;
use crate::compiler::validate_compiled_pattern_detector_indices;
use crate::types::LazyRegex;

fn compiled_pattern(detector_index: usize) -> CompiledPattern {
    CompiledPattern {
        detector_index,
        regex: LazyRegex::plain("secret_[A-Za-z0-9]{16}"),
        group: None,
        client_safe: false,
        weak_anchor: false,
        match_proves_keyword_nearby: false,
        homoglyph_variant: false,
    }
}

#[test]
fn invalid_detector_indices_fail_before_scanner_construction() {
    let ac_error = validate_compiled_pattern_detector_indices(&[compiled_pattern(2)], &[], 1)
        .expect_err("an AC pattern cannot name an absent detector")
        .to_string();
    assert_eq!(
        ac_error,
        "compiled scanner invariant violation: ac_map[0] references detector_index 2 but only 1 detector(s) are loaded. Fix: rebuild detector compilation so every compiled pattern keeps its source detector index before scanner construction completes"
    );

    let phase2_error = validate_compiled_pattern_detector_indices(
        &[],
        &[(compiled_pattern(4), vec!["secret".to_string()])],
        3,
    )
    .expect_err("a phase-2 pattern cannot name an absent detector")
    .to_string();
    assert_eq!(
        phase2_error,
        "compiled scanner invariant violation: phase2_patterns[0] references detector_index 4 but only 3 detector(s) are loaded. Fix: rebuild detector compilation so every compiled pattern keeps its source detector index before scanner construction completes"
    );
}

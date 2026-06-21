//! KH-GAP-126: Suppression vs shape-gates lack paired FP/FN pipeline twins.
//!
//! `engine_cases/suppression.rs` tests unit-level `known_example_suppressed`
//! and a few e2e EXAMPLE paths. No paired twins prove:
//!   - FN: realistic credential wrongly suppressed when shape_gates fire
//!   - FP: near-miss placeholder reaches findings when bypass_shape_gates is false

use std::path::PathBuf;

#[test]
fn suppression_shape_gate_pipeline_twin_tests_exist() {
    let adversarial = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial");
    let required = [
        "suppression_shape_gate_fp_repetitive_mask.rs",
        "suppression_shape_gate_fp_fake_sequence.rs",
        "suppression_shape_gate_fp_dashed_serial.rs",
        "suppression_shape_gate_fp_export_db_password.rs",
        "suppression_shape_gate_fn_realistic_body.rs",
        "suppression_shape_gate_fn_named_detector_hex.rs",
        "suppression_shape_gate_fn_boundary_still_fires.rs",
    ];
    let missing: Vec<_> = required
        .iter()
        .filter(|name| !adversarial.join(name).is_file())
        .copied()
        .collect();
    assert!(
        missing.is_empty(),
        "KH-GAP-126: missing suppression/shape-gate pipeline twins: {missing:?}"
    );
}

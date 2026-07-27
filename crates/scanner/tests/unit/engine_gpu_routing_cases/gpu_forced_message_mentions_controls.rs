//! KH-GAP-002 / KH-GAP-041: selected-GPU failure must cite operator controls.

#[test]
fn selected_gpu_failure_message_mentions_operator_controls() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/gpu_forced_helpers.rs"
    );
    let src = std::fs::read_to_string(path).expect("gpu_forced_helpers.rs readable");
    assert!(src.contains("--backend"));
    assert!(src.contains("--backend simd-regex"));
    assert!(!src.contains("KEYHOG_REQUIRE_GPU"));
    assert!(src.contains("silent CPU fallback is forbidden"));
    assert!(src.contains("--backend cpu-fallback"));
    assert!(src.contains("recalibrate autoroute"));
}

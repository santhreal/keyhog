//! KH-GAP-002 / KH-GAP-041: forced-GPU and require-GPU panic must cite operator controls.

#[test]
fn gpu_forced_message_mentions_operator_controls() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/gpu_forced_helpers.rs"
    );
    let src = std::fs::read_to_string(path).expect("gpu_forced_helpers.rs readable");
    assert!(src.contains("--backend"));
    assert!(src.contains("--require-gpu"));
    assert!(!src.contains("KEYHOG_REQUIRE_GPU"));
    assert!(src.contains("silent CPU fallback is forbidden"));
    assert!(src.contains("deny_silent_gpu_degrade_with_reason"));
    assert!(src.contains("Refusing to silently degrade"));
}

//! KH-GAP-002 / KH-GAP-041: forced-GPU and KEYHOG_REQUIRE_GPU panic must cite env vars.

#[test]
fn gpu_forced_message_mentions_env() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/gpu_forced.rs");
    let src = std::fs::read_to_string(path).expect("gpu_forced.rs readable");
    assert!(src.contains("KEYHOG_BACKEND="));
    assert!(src.contains("KEYHOG_REQUIRE_GPU"));
    assert!(src.contains("silent CPU fallback is forbidden"));
    assert!(src.contains("deny_gpu_runtime_degrade"));
}

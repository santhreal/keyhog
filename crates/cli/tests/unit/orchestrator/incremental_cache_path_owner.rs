#[test]
fn incremental_cache_path_uses_core_merkle_owner() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/mod.rs"
    ))
    .expect("orchestrator source readable");

    assert!(
        src.contains("keyhog_core::merkle_default_cache_path"),
        "orchestrator must use the core Merkle cache path owner"
    );
    assert!(
        !src.contains("fn default_incremental_cache_path") && !src.contains("join(\"merkle.idx\")"),
        "orchestrator must not duplicate the Merkle cache path construction"
    );
}

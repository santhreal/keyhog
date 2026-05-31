#[test]
fn fallback_always_active_seed_is_sparse_not_dense_bool_scan() {
    let module = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/mod.rs"))
        .expect("read engine mod");
    assert!(
        module.contains("fallback_always_active_indices: Vec<usize>"),
        "always-active fallback seeds must be stored as sparse indices"
    );
    assert!(
        !module.contains("fallback_always_active: Vec<bool>"),
        "dense fallback bool tables force an O(fallback-patterns) scan per chunk"
    );

    let fallback = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/fallback.rs"
    ))
    .expect("read fallback module");
    assert!(
        fallback.contains("for &index in &self.fallback_always_active_indices"),
        "fallback hot path must seed from sparse always-active indices"
    );
    assert!(
        !fallback.contains("fallback_always_active.iter().enumerate()"),
        "fallback hot path must not rescan a dense always-active table"
    );
}

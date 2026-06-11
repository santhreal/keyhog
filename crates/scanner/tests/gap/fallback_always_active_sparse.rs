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
    // The active-set probe (`has_active_fallback_patterns_for_chunk`) is the
    // recall-load-bearing no-hit admission gate. It MUST answer the per-chunk
    // question by running the real prefilter, NOT coarsely short-circuit to
    // `true` whenever any always-active detector exists. The earlier coarse
    // `!self.fallback_always_active_indices.is_empty()` short-circuit admitted
    // EVERY chunk (there are ~3100 prefix-less always-active detectors, so the
    // index set is never empty), defeating `should_scan_no_hit_chunk`; it was
    // deliberately removed (see the rationale on the probe in fallback.rs).
    assert!(
        fallback.contains("fn has_active_fallback_patterns_for_chunk"),
        "fallback must expose a per-chunk active-set admission probe"
    );
    assert!(
        !fallback.contains("!self.fallback_always_active_indices.is_empty()"),
        "active-set probe must NOT coarsely short-circuit on a non-empty always-active index set: that admits every chunk and defeats no-hit admission"
    );
    assert!(
        !fallback.contains("fallback_always_active.iter().enumerate()"),
        "fallback hot path must not rescan a dense always-active table"
    );
}

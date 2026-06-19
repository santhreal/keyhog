#[test]
fn phase2_always_active_seed_is_sparse_not_dense_bool_scan() {
    let module = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/mod.rs"))
        .expect("read engine mod");
    assert!(
        module.contains("phase2_always_active_indices: Vec<usize>"),
        "always-active phase-2 seeds must be stored as sparse indices"
    );
    assert!(
        !module.contains("phase2_always_active: Vec<bool>"),
        "dense phase-2 bool tables force an O(phase-2-patterns) scan per chunk"
    );

    // The phase-2 scan impl (hot-path seed loop + the active-set admission
    // probe) was split out of the old fallback module into `phase2_compiled.rs` under the
    // 500-LOC ceiling (Law 5); the sparse-seed invariant now lives there.
    let phase2 = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/phase2_compiled.rs"
    ))
    .expect("read phase2_compiled module");
    assert!(
        phase2.contains("for &index in &self.phase2_always_active_indices"),
        "phase-2 hot path must seed from sparse always-active indices"
    );
    // The active-set probe (`has_active_phase2_patterns_for_chunk`) is the
    // recall-load-bearing no-hit admission gate. It MUST answer the per-chunk
    // question by running the real prefilter, NOT coarsely short-circuit to
    // `true` whenever any always-active detector exists. The earlier coarse
    // `!self.phase2_always_active_indices.is_empty()` short-circuit admitted
    // EVERY chunk (there are ~3100 prefix-less always-active detectors, so the
    // index set is never empty), defeating `should_scan_no_hit_chunk`; it was
    // deliberately removed (see the rationale on the probe in phase2_compiled.rs).
    assert!(
        phase2.contains("fn has_active_phase2_patterns_for_chunk"),
        "phase-2 must expose a per-chunk active-set admission probe"
    );
    assert!(
        !phase2.contains("!self.phase2_always_active_indices.is_empty()"),
        "active-set probe must NOT coarsely short-circuit on a non-empty always-active index set: that admits every chunk and defeats no-hit admission"
    );
    assert!(
        !phase2.contains("phase2_always_active.iter().enumerate()"),
        "phase-2 hot path must not rescan a dense always-active table"
    );
}

#[test]
fn csr_u32_is_adopted_for_hot_index_maps() {
    let module = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/mod.rs"))
        .expect("read engine mod");
    let simd = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/backend_prepared.rs"
    ))
    .expect("read SIMD phase-one owner");
    let simd_prefilter = simd
        .split("pub(crate) struct SimdPhase1Prefilter")
        .nth(1)
        .expect("SIMD phase-one prefilter struct")
        .split("impl SimdPhase1Prefilter")
        .next()
        .expect("SIMD phase-one prefilter boundary");

    for field in [
        "prefix_propagation: CsrU32",
        "same_prefix_patterns: CsrU32",
        "phase2_keyword_to_patterns: CsrU32",
    ] {
        assert!(
            module.contains(field),
            "hot index map must use compact CSR storage: {field}"
        );
    }
    assert!(
        simd_prefilter.contains("index_map: super::CsrU32"),
        "the encapsulated SIMD pattern map must use compact CSR storage"
    );

    for dense_field in [
        "prefix_propagation: Vec<Vec<usize>>",
        "same_prefix_patterns: Vec<Vec<usize>>",
        "phase2_keyword_to_patterns: Vec<Vec<usize>>",
    ] {
        assert!(
            !module.contains(dense_field),
            "hot index map must not return to dense nested Vec storage: {dense_field}"
        );
    }
    assert!(!simd_prefilter.contains("index_map: Vec<Vec<usize>>"));
}

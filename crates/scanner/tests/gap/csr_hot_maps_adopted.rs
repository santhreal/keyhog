#[test]
fn csr_u32_is_adopted_for_hot_index_maps() {
    let module = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/mod.rs"))
        .expect("read engine mod");

    for field in [
        "prefix_propagation: CsrU32",
        "same_prefix_patterns: CsrU32",
        "fallback_keyword_to_patterns: CsrU32",
        "hs_index_map: CsrU32",
    ] {
        assert!(
            module.contains(field),
            "hot index map must use compact CSR storage: {field}"
        );
    }

    for dense_field in [
        "prefix_propagation: Vec<Vec<usize>>",
        "same_prefix_patterns: Vec<Vec<usize>>",
        "fallback_keyword_to_patterns: Vec<Vec<usize>>",
        "hs_index_map: Vec<Vec<usize>>",
    ] {
        assert!(
            !module.contains(dense_field),
            "hot index map must not return to dense nested Vec storage: {dense_field}"
        );
    }
}

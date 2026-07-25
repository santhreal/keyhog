//! The build log and live diagnostic must agree on the selective table size.

fn read_compile_source() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join("src/compiled_scanner/compile.rs"))
        .expect("compile source readable")
}

#[test]
fn selective_bloom_build_log_matches_live_table_size() {
    let compile = read_compile_source();
    assert!(
        compile.contains("selective literal-anchor bloom built (65536 slots / 8 KB)"),
        "the build log must name the generalized selective table and its exact size"
    );
    assert!(!compile.contains("bigram bloom built (4096 bits"));

    let status = keyhog_scanner::testing::production_bigram_prefilter_status();
    assert_eq!(status.total_slots, 65_536);
    assert_eq!(
        std::mem::size_of::<[u64; 1024]>(),
        8 * 1024,
        "the diagnostic's 65,536 bits occupy exactly 8 KB"
    );
}

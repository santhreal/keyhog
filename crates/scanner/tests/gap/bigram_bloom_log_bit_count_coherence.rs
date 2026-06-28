//! Regression: the compile-time "bigram bloom built" log states the real table
//! size, not the stale 4096-bit figure (Vector 10, coherence).
//!
//! `BigramBloom` is a 65536-bit / 8 KB / 1024-u64 DIRECT lookup table
//! (`TABLE_SLOTS = 65536`, `bits: Box<[u64; 1024]>`). The build-time debug log
//! in `compile.rs` still announced "(4096 bits ...)" — a leftover from the old
//! 4096-bit hashed bloom the type replaced (bigram_bloom.rs even documents "The
//! previous implementation used a 4096-bit bloom"). A log that misreports the
//! filter size by 16x sends anyone tuning popcount thresholds down the wrong
//! path. This pins the log to the real size and pins the size constant so the
//! two can't drift apart again.

fn read_src(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(rel)).expect("source file readable")
}

#[test]
fn bigram_bloom_build_log_matches_real_table_size() {
    let compile = read_src("src/engine/compile.rs");
    assert!(
        compile.contains("65536 slots / 8 KB direct table"),
        "the bigram-bloom build log must state the real 65536-slot / 8 KB table size"
    );
    assert!(
        !compile.contains("bigram bloom built (4096 bits"),
        "the bigram-bloom build log must not claim the stale 4096-bit figure"
    );

    // Pin the actual table size so the log and the implementation stay in sync.
    let bloom = read_src("src/bigram_bloom.rs");
    assert!(
        bloom.contains("const TABLE_SLOTS: u32 = 65536;"),
        "BigramBloom must be a 65536-slot table (the figure the log now reports)"
    );
    assert!(
        bloom.contains("bits: Box<[u64; 1024]>"),
        "BigramBloom must be 1024 u64 (8 KB), matching the logged 8 KB"
    );
}

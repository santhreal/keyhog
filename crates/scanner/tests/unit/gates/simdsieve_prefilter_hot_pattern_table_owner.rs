//! Gate `simdsieve_prefilter`: hot-pattern slot data has one owner.

#[test]
fn hot_pattern_slot_metadata_has_one_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let simdsieve = std::fs::read_to_string(root.join("simdsieve_prefilter.rs"))
        .expect("simdsieve_prefilter source readable");
    let hot_patterns = std::fs::read_to_string(root.join("engine/hot_patterns.rs"))
        .expect("engine hot_patterns source readable");

    assert!(
        simdsieve.contains("macro_rules! define_hot_pattern_tables")
            && simdsieve.contains("define_hot_pattern_tables!")
            && simdsieve.contains("HOT_PATTERN_MIN_LENGTHS")
            && simdsieve.contains("pub(crate) fn hot_pattern_index_at")
            && simdsieve.contains("const _: [(); HOT_PATTERNS.len()] = [(); HOT_PATTERN_MIN_LENGTHS.len()]"),
        "hot prefixes, slot dispatch, min lengths, and identity metadata must be generated from one simdsieve table with a compile-time length guard"
    );
    assert!(
        hot_patterns.contains("HOT_PATTERN_MIN_LENGTHS[pattern_idx]")
            && hot_patterns.contains("hot_pattern_index_at")
            && !hot_patterns.contains("fn hot_pattern_index_at")
            && !hot_patterns.contains("=> Some(")
            && !hot_patterns.contains("PER_PATTERN_MIN_LEN")
            && !hot_patterns.contains("unwrap_or(8)"),
        "engine hot-pattern dispatch must consume the shared slot resolver/min-length table and fail loud on slot drift, not keep a local fallback table"
    );
}

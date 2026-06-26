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
            && simdsieve.contains("pub(crate) fn hot_pattern_index_at")
            && simdsieve
                .contains("const _: [(); HOT_PATTERNS.len()] = [(); HOT_PATTERN_NAMES.len()]")
            && simdsieve.contains(
                "const _: [(); HOT_PATTERNS.len()] = [(); HOT_PATTERN_DETECTOR_IDS.len()]"
            )
            && simdsieve.contains(
                "const _: [(); HOT_PATTERNS.len()] = [(); HOT_PATTERN_DISPLAY_NAMES.len()]"
            ),
        "hot prefixes, slot dispatch, and identity metadata must be generated from one simdsieve table with compile-time length guards"
    );
    assert!(
        hot_patterns.contains("let slot = &self.hot_pattern_slots[pattern_idx];")
            && hot_patterns.contains("let Some(ac_map_index) = slot.ac_map_index else")
            && hot_patterns.contains("hot_pattern_index_at")
            && hot_patterns.contains("self.process_match(")
            && !hot_patterns.contains("fn hot_pattern_index_at")
            && !hot_patterns.contains("=> Some(")
            && !hot_patterns.contains("PER_PATTERN_MIN_LEN")
            && !hot_patterns.contains("HOT_PATTERN_MIN_LENGTHS")
            && !hot_patterns.contains("unwrap_or(8)"),
        "engine hot-pattern dispatch must consume the unified slot resolver (one row per slot, ac_map delegate + validator inseparable), require a canonical ac_map entry, and never keep a local fallback table"
    );
}

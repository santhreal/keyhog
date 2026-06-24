use keyhog_scanner::telemetry::{line_offset_mapping_mismatch_count, testing::reset};
use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::collect_structural_fragments_for_test;

#[test]
fn structural_mapping_offset_table_mismatch_is_counted() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    reset();

    let lines = [
        "const inert = true;",
        "const other = 1;",
        "api_key = [\"ghp_1234567890\", \"abcdefghijkl\"]",
    ];
    let source_line_offsets = [0, 20];
    let (joined, mappings) = collect_structural_fragments_for_test(
        &lines,
        &source_line_offsets,
        100,
        &FragmentCache::new(8),
    );

    assert_eq!(
        joined,
        vec!["ghp_1234567890abcdefghijkl".to_string()],
        "line-offset mismatch must not drop the recovered structural fragment"
    );
    assert_eq!(
        mappings[0].original_start_offset, 20,
        "mismatch should use the nearest known source offset instead of silently reporting byte 0"
    );
    assert_eq!(
        line_offset_mapping_mismatch_count(),
        1,
        "synthetic-line attribution fallback must be visible scanner coverage-gap telemetry"
    );

    reset();
}

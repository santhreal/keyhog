//! Keywords shorter than 4 chars are excluded from the fallback index.

use keyhog_scanner::testing::phase2_keyword_index_summary;

#[test]
fn compiler_phase2_keyword_skips_short() {
    let (has_index, mapping_len) =
        phase2_keyword_index_summary("key=[a-z0-9]{16}", vec!["id".into(), "token".into()]);
    assert!(has_index, "token keyword must build the compact index");
    assert_eq!(mapping_len, 1, "only token (len>=4) should be indexed");
}

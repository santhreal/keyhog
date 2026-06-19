//! Keywords shorter than 4 chars are excluded from fallback AC.

use keyhog_scanner::testing::phase2_keyword_ac_summary;

#[test]
fn compiler_phase2_keyword_skips_short() {
    let (has_ac, mapping_len) =
        phase2_keyword_ac_summary("key=[a-z0-9]{16}", vec!["id".into(), "token".into()]);
    assert!(has_ac, "token keyword must build AC");
    assert_eq!(mapping_len, 1, "only token (len>=4) should be indexed");
}

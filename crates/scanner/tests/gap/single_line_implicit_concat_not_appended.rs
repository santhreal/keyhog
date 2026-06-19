//! KH-GAP-013: single-line Python implicit concat joins locally but does not append
//! to preprocessed text because `any_real_join` requires lines_consumed > 1.

use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn single_line_implicit_concat_surfaces_joined_secret_in_text() {
    let text = r#"api_key = "sk-" "live_" "abcdef123456""#;
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(
        pre.text.contains("sk-live_abcdef123456"),
        "single-line implicit concat must surface joined secret in preprocessed text (KH-GAP-013); got:\n{}",
        pre.text
    );
}

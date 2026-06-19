use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn empty_input_yields_empty_preprocessed_text() {
    let pre = preprocess_multiline("", &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(pre.text.is_empty());
    assert!(pre.mappings.is_empty());
}

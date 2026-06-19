use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn xml_like_input_passthrough() {
    let text = "<config api_key=\"sk-\" + \"live\"/>";
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert_eq!(pre.text, text);
}

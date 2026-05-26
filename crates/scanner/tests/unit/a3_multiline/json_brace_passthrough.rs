use keyhog_scanner::fragment_cache::FragmentCache;
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn json_object_passthrough_without_append() {
    let text = "{\"key\": \"part1\" + \"part2\"}";
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert_eq!(pre.text, text);
}

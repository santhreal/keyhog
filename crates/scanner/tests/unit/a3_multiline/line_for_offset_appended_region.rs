use keyhog_scanner::fragment_cache::FragmentCache;
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn line_for_offset_maps_appended_joined_region() {
    let text = "const key = \"sk-\" +\n    \"live_abcdef123456\";";
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    let joined_offset = pre
        .text
        .find("sk-live_abcdef123456")
        .expect("joined secret present");
    assert_eq!(pre.line_for_offset(joined_offset), Some(1));
}

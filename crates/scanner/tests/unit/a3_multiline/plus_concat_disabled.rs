use keyhog_scanner::fragment_cache::FragmentCache;
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn plus_concat_off_preserves_separate_literals() {
    let text = r#"key = "part1" + "part2""#;
    let cfg = MultilineConfig {
        plus_concatenation: false,
        ..Default::default()
    };
    let pre = preprocess_multiline(text, &cfg, &FragmentCache::new(100));
    assert!(pre.text.contains("part1"));
    assert!(pre.text.contains("part2"));
    assert!(!pre.text.contains("part1part2"));
}

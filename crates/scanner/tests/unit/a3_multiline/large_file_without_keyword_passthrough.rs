use keyhog_scanner::fragment_cache::FragmentCache;
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn large_file_without_secret_keywords_passthrough() {
    let line = "x".repeat(100);
    let text = (0..50).map(|_| line.as_str()).collect::<Vec<_>>().join("\n");
    assert!(text.len() > 4096);
    let pre = preprocess_multiline(&text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert_eq!(pre.text, text);
}

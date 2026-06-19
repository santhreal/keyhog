use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn template_literal_fragments_surface_secret_prefix() {
    let text = r#"const key = `sk-proj-${id}abcdef123456`;"#;
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(pre.text.contains("sk-proj-"));
    assert!(pre.text.contains("abcdef123456"));
}

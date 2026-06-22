use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn parenthesized_unclosed_block_does_not_hide_later_block() {
    let mut lines = vec!["broken = (".to_string()];
    for part in 0..20 {
        lines.push(format!("    \"noise-{part:02}\""));
    }
    lines.extend([
        "token = (".to_string(),
        "    \"sk-proj-\"".to_string(),
        "    \"abcdef123456\"".to_string(),
        "    \"7890abcdef\"".to_string(),
        ")".to_string(),
    ]);

    let text = lines.join("\n");
    let pre = preprocess_multiline(&text, &MultilineConfig::default(), &FragmentCache::new(100));

    assert!(
        pre.text.contains("sk-proj-abcdef1234567890abcdef"),
        "unclosed parenthesized literal block must not hide a later valid block; got:\n{}",
        pre.text
    );
}

use keyhog_scanner::fragment_cache::FragmentCache;
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn backslash_continuation_off_leaves_split_secret() {
    let text = "key = 'sk-proj-' + \\\n    'abcdef1234567890'";
    let cfg = MultilineConfig { backslash_continuation: false, ..Default::default() };
    let pre = preprocess_multiline(text, &cfg, &FragmentCache::new(100));
    assert!(!pre.text.contains("sk-proj-abcdef1234567890"));
}

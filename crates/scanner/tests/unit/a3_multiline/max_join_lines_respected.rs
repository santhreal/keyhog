use keyhog_scanner::fragment_cache::FragmentCache;
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn max_join_lines_caps_concatenation_chain() {
    let parts: Vec<String> = (0..8).map(|i| format!("    \"p{i}\" +")).collect();
    let text = format!("key = \"start\" +\n{}\n    \"end\";", parts.join("\n"));
    let cfg = MultilineConfig {
        max_join_lines: 2,
        ..Default::default()
    };
    let pre = preprocess_multiline(&text, &cfg, &FragmentCache::new(100));
    assert!(!pre.text.contains("startp0p1p2p3p4p5p6end"));
}

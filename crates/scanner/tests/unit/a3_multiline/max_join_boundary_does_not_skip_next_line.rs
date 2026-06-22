use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn max_join_boundary_does_not_skip_next_line() {
    let text =
        "prefix = \"aa\" +\n    \"bb\" +\ntoken = \"ghp_\" +\n    \"ABCDEFGHIJKLMNO1234567890\";";
    let cfg = MultilineConfig {
        max_join_lines: 2,
        ..Default::default()
    };

    let pre = preprocess_multiline(text, &cfg, &FragmentCache::new(100));

    assert!(
        pre.text.contains("ghp_ABCDEFGHIJKLMNO1234567890"),
        "line immediately after a capped chain must still be processed; got:\n{}",
        pre.text
    );
}

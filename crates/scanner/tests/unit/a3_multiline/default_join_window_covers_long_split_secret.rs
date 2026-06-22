use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn default_join_window_covers_long_split_secret() {
    let parts = [
        "ghp_", "ABCDE", "FGHIJ", "KLMNO", "PQRST", "UVWXY", "Z0123", "45678", "9abcd", "efghi",
        "jklmn", "opqrs",
    ];
    let mut lines = Vec::new();
    for (idx, part) in parts.iter().enumerate() {
        let suffix = if idx + 1 == parts.len() { ";" } else { " +" };
        let prefix = if idx == 0 { "token = " } else { "    " };
        lines.push(format!("{prefix}\"{part}\"{suffix}"));
    }

    let pre = preprocess_multiline(
        lines.join("\n"),
        &MultilineConfig::default(),
        &FragmentCache::new(100),
    );

    assert!(
        pre.text.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrs"),
        "default multiline window must reassemble secrets split across more than 10 lines; got:\n{}",
        pre.text
    );
}

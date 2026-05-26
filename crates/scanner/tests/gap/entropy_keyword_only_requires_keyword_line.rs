//! KH-GAP-017: keyword-context entropy must not fire without keyword assignment line.

use keyhog_scanner::entropy::{find_entropy_secrets, HIGH_ENTROPY_THRESHOLD};

#[test]
fn entropy_keyword_only_requires_keyword_line() {
    let secret = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkLmnop";
    let text = format!("unrelated_label={secret}
");
    let matches = find_entropy_secrets(
        &text,
        16,
        2,
        HIGH_ENTROPY_THRESHOLD,
        &["API_KEY".to_string()],
        &[],
        &[],
    );
    assert!(
        matches.is_empty(),
        "entropy must not keyword-anchor on lines without secret keyword: {:?}",
        matches
    );
}

//! Inline (?i) flag is stripped before prefix extraction.

use keyhog_scanner::compiler::extract_literal_prefixes;

#[test]
fn compiler_extract_prefix_inline_flag_strip() {
    let prefixes = extract_literal_prefixes("(?i)ghp_[A-Za-z0-9]{36}");
    assert_eq!(prefixes, vec!["ghp_".to_string()]);
}

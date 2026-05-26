//! Alternation prefix extractor handles nested groups in regex head.

use keyhog_scanner::compiler::extract_literal_prefixes;

#[test]
fn compiler_alternation_rewrite_nested_groups() {
    let prefixes = extract_literal_prefixes("(?:abc(?:\\d{2})|def)body");
    assert!(
        !prefixes.is_empty(),
        "alternation with nested group must still yield literal prefix(es): {prefixes:?}"
    );
    assert!(
        prefixes.iter().any(|p| p.starts_with("abc") || p.starts_with("def")),
        "expected abc or def branch prefix, got {prefixes:?}"
    );
}

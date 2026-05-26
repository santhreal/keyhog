//! Alternation prefix extractor returns both AWS key prefixes.

use keyhog_scanner::compiler::extract_literal_prefixes;

#[test]
fn compiler_extract_prefix_alternation_akia_asia() {
    let prefixes = extract_literal_prefixes("(AKIA|ASIA)[A-Z0-9]{16}");
    assert!(prefixes.contains(&"AKIA".to_string()), "missing AKIA: {prefixes:?}");
    assert!(prefixes.contains(&"ASIA".to_string()), "missing ASIA: {prefixes:?}");
}

//! Inner literal extractor finds mid-pattern AWS anchor.

use keyhog_scanner::testing::extract_inner_literals;

#[test]
fn compiler_inner_literal_akia_mid_pattern() {
    let lits = extract_inner_literals(r"[a-zA-Z0-9]{20}_AKIA[A-Z0-9]{16}");
    assert_eq!(lits, vec!["_AKIA"]);
}

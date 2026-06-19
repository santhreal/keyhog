//! Shorter literal prefix propagates to longer literals.

use keyhog_scanner::testing::build_prefix_propagation;

#[test]
fn compiler_build_prefix_propagation_longer_extends() {
    let literals = vec!["gh".into(), "ghp_".into()];
    let map = build_prefix_propagation(&literals);
    assert_eq!(map[0], vec![1], "gh must propagate to ghp_");
    assert!(
        map[1].is_empty(),
        "longer literal must not propagate upward"
    );
}

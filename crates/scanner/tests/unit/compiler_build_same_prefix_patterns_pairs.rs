//! Duplicate literals map to sibling pattern indices.

use keyhog_scanner::compiler::build_same_prefix_patterns;

#[test]
fn compiler_build_same_prefix_patterns_pairs() {
    let literals = vec!["ghp_".into(), "ghp_".into(), "xoxb-".into()];
    let map = build_same_prefix_patterns(&literals);
    assert_eq!(map[0], vec![1]);
    assert_eq!(map[1], vec![0]);
    assert!(map[2].is_empty());
}

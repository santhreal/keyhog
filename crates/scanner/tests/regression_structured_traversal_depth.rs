//! Migrated from the inline `owner_tests` module in `structured/parsers.rs`
//! (removed to satisfy `structured_parsers_no_inline_tests`). The JSON
//! (tfstate/jupyter) and YAML (k8s/compose) recursion guards both read THIS
//! constant; it was previously two separate consts with the same value — a
//! same-value divergence risk. Locked to one owner at 256, pinned through the
//! `crate::testing` facade.

use keyhog_scanner::testing::structured_max_traversal_depth_for_test as max_traversal_depth;

#[test]
fn structured_traversal_depth_has_one_owner() {
    assert_eq!(max_traversal_depth(), 256);
}

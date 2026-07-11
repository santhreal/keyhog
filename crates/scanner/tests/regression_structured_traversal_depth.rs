use keyhog_scanner::testing::structured_max_traversal_depth_for_test;

#[test]
fn structured_traversal_depth_has_one_owner() {
    assert_eq!(structured_max_traversal_depth_for_test(), 256);
}

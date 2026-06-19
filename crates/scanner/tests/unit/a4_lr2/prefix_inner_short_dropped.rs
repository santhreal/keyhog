use keyhog_scanner::testing::extract_inner_literals;

#[test]
fn prefix_inner_short_dropped() {
    assert!(extract_inner_literals(r"wx[a-f0-9]{16}").is_empty());
}

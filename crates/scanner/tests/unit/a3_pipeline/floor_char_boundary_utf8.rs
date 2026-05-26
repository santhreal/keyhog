use keyhog_scanner::floor_char_boundary;

#[test]
fn floor_char_boundary_never_splits_utf8_codepoint() {
    let text = "hello 🦀 world";
    let crab_start = text.find('🦀').unwrap();
    assert_eq!(floor_char_boundary(text, crab_start + 1), crab_start);
}

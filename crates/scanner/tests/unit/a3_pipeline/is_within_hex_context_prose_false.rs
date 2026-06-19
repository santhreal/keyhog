use keyhog_scanner::testing::is_within_hex_context;

#[test]
fn hex_in_prose_is_false() {
    let data = "value is 0123456789abcdef today";
    let target = "0123456789abcdef";
    let start = data.find(target).unwrap();
    let end = start + target.len();
    assert!(!is_within_hex_context(data, start, end));
}

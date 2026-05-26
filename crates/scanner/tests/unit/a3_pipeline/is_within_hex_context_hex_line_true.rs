use keyhog_scanner::is_within_hex_context;

#[test]
fn long_hex_in_hex_line_is_true() {
    let data = "deadbeef-cafef00d-0123456789abcdef-deadbeef";
    let target = "0123456789abcdef";
    let start = data.find(target).unwrap();
    let end = start + target.len();
    assert!(is_within_hex_context(data, start, end));
}

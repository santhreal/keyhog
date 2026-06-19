use keyhog_scanner::testing::is_within_hex_context;

#[test]
fn sub_sixteen_byte_match_rejected() {
    let data = "deadbeef AKIA1234 deadbeef";
    let start = data.find("AKIA1234").unwrap();
    let end = start + "AKIA1234".len();
    assert!(!is_within_hex_context(data, start, end));
}

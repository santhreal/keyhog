use keyhog_scanner::is_within_hex_context;

#[test]
fn match_surrounded_by_hex_run_is_hex_context() {
    let data = "deadbeef0123456789abcdef01234567";
    assert!(is_within_hex_context(data, 8, 24));
}

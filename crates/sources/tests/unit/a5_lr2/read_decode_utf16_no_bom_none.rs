#[test]
fn read_decode_utf16_no_bom_none() {
    assert!(keyhog_sources::testing::decode_utf16(b"ab").is_none());
}

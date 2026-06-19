use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn read_decode_utf16_no_bom_none() {
    assert!(TestApi.decode_utf16(b"ab").is_none());
}

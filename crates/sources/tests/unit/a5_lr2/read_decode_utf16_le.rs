use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn read_decode_utf16_le() {
    let s="hi"; let mut b=vec![0xFF,0xFE]; for u in s.encode_utf16() {{ b.extend(u.to_le_bytes()); }} assert_eq!(TestApi.decode_utf16(&b).as_deref(), Some("hi"));
}

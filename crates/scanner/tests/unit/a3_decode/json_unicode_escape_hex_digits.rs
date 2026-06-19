//! JSON `\u` unescape exercises shared take_hex_digits helper.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn json_unicode_escape_decodes_uppercase_hex() {
    let text = r#"{"token": "prefix\u0041\u0042\u0043\u0044"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded.iter().any(|c| c.data.contains("ABCD")),
        "json \\u escapes must decode via take_hex_digits"
    );
}

//! Unicode escape decoder must use JSON-compatible simple escape semantics.

use keyhog_scanner::testing::unicode_escape_decode;

#[test]
fn unicode_escape_decodes_simple_control_escapes() {
    let decoded = unicode_escape_decode(r#"line\u0041\n\t\r\b\fend"#)
        .expect("unicode escape decoder should accept valid simple escapes");

    assert_eq!(decoded, "lineA\n\t\r\x08\x0cend");
}

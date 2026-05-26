//! Quoted base64 literals are extracted.

use keyhog_scanner::decode::find_base64_strings;

#[test]
fn quoted_base64_found() {
    let text = r#""c2stcHJvai1hYmMxMjM=""#;
    let matches = find_base64_strings(text, 12);
    assert_eq!(matches.len(), 1);
}

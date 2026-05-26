//! find_base64_strings discovers assignment-shaped blobs.

use keyhog_scanner::decode::find_base64_strings;

#[test]
fn assignment_value_base64_found() {
    let text = "token = c2stcHJvai1hYmMxMjM=";
    let matches = find_base64_strings(text, 12);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, "c2stcHJvai1hYmMxMjM=");
}

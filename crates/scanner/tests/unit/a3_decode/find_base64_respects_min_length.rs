//! Shorter-than-minimum base64 blobs are filtered out.

use keyhog_scanner::decode::find_base64_strings;

#[test]
fn short_base64_below_min_length_excluded() {
    let text = "key = YWJj"; // "abc" - too short at min 12
    let matches = find_base64_strings(text, 12);
    assert!(matches.is_empty());
}

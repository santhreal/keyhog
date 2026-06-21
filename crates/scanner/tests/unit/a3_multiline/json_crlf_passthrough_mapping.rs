use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn json_crlf_passthrough_uses_byte_exact_identity_mappings() {
    let text = "{\r\n  \"api_key\": \"Xk9pQ2mZ7vL4nR8wT6yB3cF1dG5hJ0aS\"\r\n}\r\n";
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));

    assert_eq!(pre.text, text);
    assert_eq!(pre.original_end, text.len());

    let line2_start = text.find("  \"api_key\"").expect("line 2 starts");
    let line3_start = text.find("}\r\n").expect("line 3 starts");
    assert_eq!(line2_start, 3, "CRLF line 2 must start after full \\r\\n");
    assert_eq!(
        pre.mappings[0].end_offset, line2_start,
        "line 1 mapping must include the full CRLF terminator"
    );
    assert_eq!(pre.mappings[1].start_offset, line2_start);
    assert_eq!(
        pre.mappings[1].end_offset, line3_start,
        "line 2 mapping must advance by the full CRLF terminator"
    );
    assert_eq!(pre.line_for_offset(line2_start), Some(2));
    assert_eq!(pre.line_for_offset(line3_start), Some(3));
}

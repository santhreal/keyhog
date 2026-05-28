//! R5-T-SCAN concat reassembly: negative concat near miss.

#[path = "../oracle_support.rs"]
mod oracle_support;
use oracle_support::scan_text;

#[test]
fn concat_negative_concat_near_miss() {
    let body = r#"head = "AKIA"
tail = "SHORT"
key = head + tail
"#;
    let matches = scan_text(body, "concat.txt");

    let hits: Vec<_> = matches.iter().filter(|m| m.detector_id.as_ref() == "aws-access-key").collect();
    assert!(hits.is_empty(), "concat near-miss must stay silent; got {:?}", hits);
}

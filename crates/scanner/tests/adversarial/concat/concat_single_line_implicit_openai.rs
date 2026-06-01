//! R5-T-SCAN concat reassembly: single line implicit openai.

use crate::adversarial::oracle_support::scan_text;

#[test]
fn concat_single_line_implicit_openai() {
    let body = r#"key = "sk-proj-" "abcdefghijklmnopqrstuvwxyz1234567890ABCD"
"#;
    let matches = scan_text(body, "concat.txt");

    assert!(
        matches.iter().any(|m| m.detector_id.as_ref() == "openai-api-key" && m.credential.as_ref() == "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
        "openai-api-key concat must surface sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD; matches={:?}",
        matches.iter().map(|m| (m.detector_id.as_ref(), m.credential.as_ref())).collect::<Vec<_>>()
    );
}

//! R5-T-SCAN concat reassembly: python plus aws.

use crate::adversarial::oracle_support::scan_text;

#[test]
fn concat_python_plus_aws() {
    let body = r#"head = "AKIA"
tail = "QYLPMN5HFIQR7XYA"
key = head + tail
"#;
    let matches = scan_text(body, "concat.txt");

    assert!(
        matches
            .iter()
            .any(|m| m.detector_id.as_ref() == "aws-access-key"
                && m.credential.as_ref() == "AKIAQYLPMN5HFIQR7XYA"),
        "aws-access-key concat must surface AKIAQYLPMN5HFIQR7XYA; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

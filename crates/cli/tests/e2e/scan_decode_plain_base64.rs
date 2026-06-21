//! E2E: generic decode-through works on a plain file and reports source offsets.

use crate::e2e::support::{scan_path, scan_text_file, write_temp_file};

#[test]
fn scan_plain_file_base64_decodes_secret_at_encoded_source_offset() {
    const SECRET: &str = "AKIAQYLPMN5HFIQR7XYA";
    const ENCODED_ASSIGNMENT: &str = "QVdTX0FDQ0VTU19LRVlfSUQ9QUtJQVFZTFBNTjVIRklRUjdYWUE=";
    let text = format!("base64_payload = \"{ENCODED_ASSIGNMENT}\"\n");
    let encoded_start = text
        .find(ENCODED_ASSIGNMENT)
        .expect("fixture contains encoded assignment");
    let encoded_end = encoded_start + ENCODED_ASSIGNMENT.len();

    let (stdout, stderr, code) = scan_text_file(&text, &[]);
    assert_eq!(
        code,
        Some(1),
        "plain base64 file must surface the decoded AWS key; stderr={stderr}; stdout={stdout}"
    );

    let findings = serde_json::from_str::<serde_json::Value>(&stdout)
        .expect("json")
        .as_array()
        .expect("array")
        .clone();
    let aws = findings
        .iter()
        .find(|finding| {
            finding["detector_id"] == "aws-access-key"
                && finding["credential_redacted"]
                    .as_str()
                    .is_some_and(|redacted| redacted.contains(&SECRET[..4]))
        })
        .unwrap_or_else(|| panic!("missing decoded AWS key finding; findings={findings:#?}"));

    assert_eq!(aws["location"]["line"], 1);
    let offset = aws["location"]["offset"]
        .as_u64()
        .expect("location.offset must be numeric") as usize;
    assert!(
        offset < text.len(),
        "decoded finding offset {offset} must be inside the {}-byte source file",
        text.len()
    );
    assert!(
        (encoded_start..encoded_end).contains(&offset),
        "decoded finding offset {offset} must point inside the encoded base64 run \
         {encoded_start}..{encoded_end} in the source file"
    );
}

#[test]
fn scan_k8s_secret_base64_decodes_secret_at_encoded_source_offset() {
    const ENCODED_ASSIGNMENT: &str = "QVdTX0FDQ0VTU19LRVlfSUQ9QUtJQVFZTFBNTjVIRklRUjdYWUE=";
    let text = format!(
        "apiVersion: v1\n\
         kind: Secret\n\
         metadata:\n\
         \x20\x20name: aws-creds\n\
         data:\n\
         \x20\x20aws_credentials: {ENCODED_ASSIGNMENT}\n"
    );
    let encoded_start = text
        .find(ENCODED_ASSIGNMENT)
        .expect("fixture contains encoded assignment");
    let encoded_end = encoded_start + ENCODED_ASSIGNMENT.len();
    let (_dir, path) = write_temp_file("k8s-secret.yaml", &text);

    let output = scan_path(&path, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "k8s Secret base64 data must surface the decoded AWS key; stderr={stderr}; stdout={stdout}"
    );

    let findings = serde_json::from_str::<serde_json::Value>(&stdout)
        .expect("json")
        .as_array()
        .expect("array")
        .clone();
    let aws = findings
        .iter()
        .find(|finding| finding["detector_id"] == "aws-access-key")
        .unwrap_or_else(|| panic!("missing decoded AWS key finding; findings={findings:#?}"));

    assert_eq!(aws["location"]["line"], 6);
    let offset = aws["location"]["offset"]
        .as_u64()
        .expect("location.offset must be numeric") as usize;
    assert!(
        offset < text.len(),
        "decoded k8s finding offset {offset} must be inside the {}-byte source file",
        text.len()
    );
    assert!(
        (encoded_start..encoded_end).contains(&offset),
        "decoded k8s finding offset {offset} must point inside the encoded base64 run \
         {encoded_start}..{encoded_end} in the source file"
    );
}

//! Gate base64 classifier hot path: one candidate scan collects variant facts.

#[test]
fn decode_base64_classifier_scans_candidate_once() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/base64.rs");
    let src = std::fs::read_to_string(path).expect("decode/base64.rs source readable");
    let classifier = src
        .split("fn classify_base64(candidate: &str)")
        .nth(1)
        .and_then(|tail| tail.split("/// Maximum base64 input length").next())
        .expect("classify_base64 body is extractable");

    assert!(
        classifier.contains("scan_base64_candidate(candidate)?"),
        "base64 variant classification must collect alphabet/padding facts in one scan"
    );
    assert!(
        !classifier.contains("candidate.contains(") && !classifier.contains("candidate.find("),
        "base64 classifier must not re-scan the candidate with contains/find"
    );
}

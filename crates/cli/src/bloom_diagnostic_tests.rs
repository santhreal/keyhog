use super::{finding_digest, FindingIdentity};

fn identity() -> FindingIdentity {
    FindingIdentity {
        detector_id: "aws-access-key".to_string(),
        file_path: Some("data/repo/source.rs#record-7".to_string()),
        line: Some(42),
        span_start: 1_024,
        span_end: 1_044,
        credential_sha256:
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    }
}

#[test]
fn finding_digest_binds_detector_file_line_span_and_credential_digest() {
    let original = identity();
    let expected = finding_digest(std::slice::from_ref(&original));

    let mut variants = Vec::new();
    let mut changed = original.clone();
    changed.detector_id = "github-pat".to_string();
    variants.push(changed);
    let mut changed = original.clone();
    changed.file_path = Some("data/repo/other.rs#record-7".to_string());
    variants.push(changed);
    let mut changed = original.clone();
    changed.line = Some(43);
    variants.push(changed);
    let mut changed = original.clone();
    changed.span_start += 1;
    variants.push(changed);
    let mut changed = original.clone();
    changed.span_end += 1;
    variants.push(changed);
    let mut changed = original;
    changed.credential_sha256 =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    variants.push(changed);

    for variant in variants {
        assert_ne!(
            finding_digest(&[variant]),
            expected,
            "every required finding identity field must affect the digest"
        );
    }
}

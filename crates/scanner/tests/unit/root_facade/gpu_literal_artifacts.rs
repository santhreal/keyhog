use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::compile_gpu_literal_artifacts_default;
use vyre_libs::scan::{GpuLiteralSet, MatchEngineCache};

#[test]
fn gpu_literal_artifacts_round_trip_through_vyre_bytes() {
    let detectors = vec![
        DetectorSpec {
            tests: Vec::new(),
            id: "aws-access-key-id".into(),
            name: "AWS access key ID".into(),
            service: "aws".into(),
            severity: Severity::High,
            patterns: vec![PatternSpec {
                regex: "AKIA[0-9A-Z]{16}".into(),
                description: None,
                group: None,
                client_safe: false,
                weak_anchor: false,
            }],
            companions: vec![],
            verify: None,
            keywords: vec!["AKIA".into()],
            min_confidence: None,
            ..Default::default()
        },
        DetectorSpec {
            tests: Vec::new(),
            id: "github-token".into(),
            name: "GitHub token".into(),
            service: "github".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "ghp_[A-Za-z0-9]{36}".into(),
                description: None,
                group: None,
                client_safe: false,
                weak_anchor: false,
            }],
            companions: vec![],
            verify: None,
            keywords: vec!["ghp_".into()],
            min_confidence: None,
            ..Default::default()
        },
    ];

    let artifacts = compile_gpu_literal_artifacts_default(&detectors)
        .expect("artifact compilation should reuse the scanner compiler");
    let literal = artifacts
        .literal
        .as_ref()
        .expect("detector literals should produce a main GPU artifact");
    assert!(
        literal.cache_key.starts_with("lit-"),
        "main artifact cache key must match the runtime lazy matcher prefix, got {}",
        literal.cache_key
    );
    assert_eq!(literal.wire_magic, GpuLiteralSet::WIRE_MAGIC);
    assert_eq!(literal.wire_version, GpuLiteralSet::WIRE_VERSION);
    assert!(
        literal.bytes.len() >= GpuLiteralSet::WIRE_MAGIC.len(),
        "main artifact bytes must include VYRE wire header"
    );
    assert_eq!(&literal.bytes[..4], &GpuLiteralSet::WIRE_MAGIC);
    GpuLiteralSet::from_bytes(&literal.bytes)
        .expect("main GPU artifact bytes must reload through VYRE");

    assert!(
        artifacts.positioned_literal.is_none(),
        "positioned rows must live in the single fused runtime artifact"
    );

    assert!(
        literal.pattern_count >= detectors.len(),
        "main artifact must include detector literal rows, got {}",
        literal.pattern_count
    );
    assert!(literal.pattern_count > detectors.len());
}

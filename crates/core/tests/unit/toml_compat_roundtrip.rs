//! Detector spec roundtrip: TOML -> DetectorSpec -> JSON -> DetectorSpec (via serde).
use keyhog_core::{
    load_detectors_from_str, AuthSpec, CompanionSpec, DetectorFile, DetectorSpec, HeaderSpec,
    HttpMethod, MetadataSpec, PatternSpec, Severity, SuccessSpec, VerifySpec,
};

#[test]
fn toml_compat_detector_roundtrip_minimal() {
    let toml_str = r#"
[detector]
id = "minimal-test"
name = "Minimal Test"
service = "test-svc"
severity = "high"
keywords = ["prefix_"]

[[detector.patterns]]
regex = "prefix_[A-Z0-9]{16}"
"#;

    let specs = load_detectors_from_str(toml_str).expect("load");
    assert_eq!(specs.len(), 1);

    let spec = &specs[0];
    assert_eq!(spec.id, "minimal-test");
    assert_eq!(spec.name, "Minimal Test");
    assert_eq!(spec.service, "test-svc");
    assert_eq!(spec.severity, Severity::High);
    assert_eq!(spec.keywords, vec!["prefix_"]);
    assert_eq!(spec.patterns.len(), 1);
    assert_eq!(spec.patterns[0].regex, "prefix_[A-Z0-9]{16}");
    assert_eq!(spec.patterns[0].description, None);
    assert_eq!(spec.patterns[0].group, None);
    assert!(!spec.patterns[0].client_safe);
    assert!(spec.companions.is_empty());
    assert!(spec.verify.is_none());
    assert_eq!(spec.min_confidence, None);

    // Roundtrip through serde: DetectorFile -> JSON -> DetectorFile
    let detector_file = DetectorFile {
        detector: spec.clone(),
    };
    let json = serde_json::to_string(&detector_file).expect("serialize");
    let roundtrip: DetectorFile = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(roundtrip.detector.id, spec.id);
    assert_eq!(roundtrip.detector.patterns, spec.patterns);
}

#[test]
fn toml_compat_detector_roundtrip_with_all_fields() {
    let toml_str = r#"
[detector]
id = "full-test"
name = "Full Test"
service = "test-svc"
severity = "critical"
keywords = ["api_key_", "secret_"]
min_confidence = 0.85

[[detector.patterns]]
regex = "api_key_([A-Za-z0-9]{32})"
description = "Main pattern"
group = 1
client_safe = false

[[detector.patterns]]
regex = "secret_[A-Z0-9]{48}"
client_safe = true

[[detector.companions]]
name = "account_id"
regex = "account:([0-9]{10})"
within_lines = 10
required = true

[detector.verify]
method = "POST"
url = "https://api.test.com/verify"
timeout_ms = 5000

[detector.verify.success]
status = 200
body_contains = "valid"

[[detector.verify.headers]]
name = "Authorization"
value = "Bearer {{match}}"

[[detector.verify.metadata]]
name = "account"
json_path = "$.account_id"
"#;

    let specs = load_detectors_from_str(toml_str).expect("load");
    assert_eq!(specs.len(), 1);

    let spec = &specs[0];
    assert_eq!(spec.id, "full-test");
    assert_eq!(spec.min_confidence, Some(0.85));
    assert_eq!(spec.patterns.len(), 2);
    assert_eq!(spec.patterns[0].group, Some(1));
    assert_eq!(spec.patterns[0].description, Some("Main pattern".into()));
    assert!(!spec.patterns[0].client_safe);
    assert!(spec.patterns[1].client_safe);
    assert_eq!(spec.companions.len(), 1);
    assert_eq!(spec.companions[0].name, "account_id");
    assert_eq!(spec.companions[0].within_lines, 10);
    assert!(spec.companions[0].required);

    let verify = spec.verify.as_ref().expect("verify present");
    assert_eq!(verify.method, Some(HttpMethod::Post));
    assert_eq!(verify.url, Some("https://api.test.com/verify".into()));
    assert_eq!(verify.timeout_ms, Some(5000));
    assert_eq!(verify.headers.len(), 1);
    assert_eq!(verify.headers[0].name, "Authorization");
    assert_eq!(verify.metadata.len(), 1);

    let success = verify.success.as_ref().expect("success present");
    assert_eq!(success.status, Some(200));
    assert_eq!(success.body_contains, Some("valid".into()));

    // Roundtrip through serde
    let detector_file = DetectorFile {
        detector: spec.clone(),
    };
    let json = serde_json::to_string(&detector_file).expect("serialize");
    let roundtrip: DetectorFile = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(roundtrip.detector.id, spec.id);
    assert_eq!(roundtrip.detector.min_confidence, spec.min_confidence);
    assert_eq!(roundtrip.detector.patterns.len(), spec.patterns.len());
    assert_eq!(roundtrip.detector.companions.len(), spec.companions.len());
    assert!(roundtrip.detector.verify.is_some());
}

#[test]
fn toml_compat_detector_roundtrip_with_optional_defaults() {
    // Test that optional fields omitted in TOML deserialize to sensible defaults
    let toml_str = r#"
[detector]
id = "defaults-test"
name = "Defaults Test"
service = "test"
severity = "medium"
keywords = []

[[detector.patterns]]
regex = "[0-9]{10}"
"#;

    let specs = load_detectors_from_str(toml_str).expect("load");
    let spec = &specs[0];

    // Verify defaults
    assert_eq!(spec.companions.len(), 0);
    assert!(spec.verify.is_none());
    assert_eq!(spec.min_confidence, None);
    assert!(spec.keywords.is_empty());
    assert!(!spec.patterns[0].client_safe);
    assert_eq!(spec.patterns[0].group, None);
    assert_eq!(spec.patterns[0].description, None);
}

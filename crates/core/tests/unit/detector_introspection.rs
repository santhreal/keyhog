//! Detector introspection preserves declarations while redacting fixture bytes.

use keyhog_core::{DetectorSpec, DetectorTestSpec, PatternSpec, Severity};

#[test]
fn introspection_uses_the_declared_spec_and_redacts_test_credentials() {
    let detector = DetectorSpec {
        id: "introspection-owner".to_string(),
        name: "Introspection owner".to_string(),
        service: "fixture".to_string(),
        severity: Severity::High,
        keywords: vec!["credential".to_string()],
        simdsieve_prefixes: vec!["fx_".to_string()],
        patterns: vec![PatternSpec {
            regex: "fx_[A-Za-z0-9]{20}".to_string(),
            description: Some("fixture pattern".to_string()),
            group: Some(0),
            required_literals: Vec::new(),
            client_safe: true,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        min_confidence: Some(0.91),
        entropy_high: Some(4.25),
        entropy_policy_priority: Some(73),
        bpe_enabled: Some(false),
        max_len: Some(96),
        allowlist_paths: vec!["vendor/".to_string()],
        tests: vec![DetectorTestSpec {
            test_positive: Some("fx_SUPERSECRET012345678".to_string()),
            test_negative: Some("fx_not-a-real-credential".to_string()),
        }],
        ..DetectorSpec::default()
    };

    let declared = serde_json::to_value(&detector).expect("declared detector serializes");
    let introspection =
        serde_json::to_value(detector.introspection()).expect("introspection serializes");

    assert_eq!(introspection["id"], declared["id"]);
    assert_eq!(introspection["patterns"], declared["patterns"]);
    assert_eq!(
        introspection["policy"]["min_confidence"],
        declared["min_confidence"]
    );
    assert_eq!(
        introspection["policy"]["entropy_high"],
        declared["entropy_high"]
    );
    assert_eq!(
        introspection["policy"]["entropy_policy_priority"],
        declared["entropy_policy_priority"]
    );
    assert_eq!(
        introspection["policy"]["bpe_enabled"],
        declared["bpe_enabled"]
    );
    assert_eq!(introspection["policy"]["max_len"], declared["max_len"]);
    assert_eq!(
        introspection["policy"]["allowlist_paths"],
        declared["allowlist_paths"]
    );
    assert_eq!(
        introspection["test_contracts"],
        serde_json::json!([{"positive": true, "negative": true}])
    );

    let rendered = serde_json::to_string(&introspection).expect("introspection renders");
    assert!(!rendered.contains("SUPERSECRET"));
    assert!(!rendered.contains("not-a-real-credential"));
}

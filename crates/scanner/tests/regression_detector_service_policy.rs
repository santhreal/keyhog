use keyhog_core::{Chunk, DetectorSpec, MatchLocation, PatternSpec, RawMatch, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::Arc;

fn scanner_for(service: &str) -> CompiledScanner {
    CompiledScanner::compile(vec![DetectorSpec {
        id: "opaque-detector-id".into(),
        name: "Opaque detector".into(),
        service: service.into(),
        severity: Severity::High,
        min_confidence: Some(0.0),
        patterns: vec![PatternSpec {
            regex: "opaque=([a]{24})".into(),
            group: Some(1),
            required_literals: Vec::new(),
            ..PatternSpec::default()
        }],
        keywords: vec!["opaque".into()],
        ..DetectorSpec::default()
    }])
    .expect("compile custom detector")
}

fn raw_match(detector_id: &str, service: &str, credential: &str, confidence: f64) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_id),
        service: Arc::from(service),
        severity: Severity::High,
        credential: credential.into(),
        credential_hash: keyhog_core::sha256_hash(credential),
        companions: Default::default(),
        location: MatchLocation {
            source: Arc::from("test"),
            file_path: Some(Arc::from("application.conf")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(confidence),
    }
}

#[test]
fn reporting_service_does_not_control_generic_execution_policy() {
    let chunk = Chunk {
        data: "opaque=aaaaaaaaaaaaaaaaaaaaaaaa".into(),
        metadata: keyhog_core::ChunkMetadata::default(),
    };

    let generic = scanner_for("generic").scan_with_backend(&chunk, ScanBackend::CpuFallback);
    assert_eq!(
        generic.len(),
        1,
        "service is reporting taxonomy, not execution policy"
    );
    assert_eq!(generic[0].detector_id.as_ref(), "opaque-detector-id");

    let named = scanner_for("opaque-service").scan_with_backend(&chunk, ScanBackend::CpuFallback);
    assert_eq!(
        named.len(),
        1,
        "changing only reporting service cannot change findings"
    );
    assert_eq!(named[0].detector_id.as_ref(), "opaque-detector-id");
    assert_eq!(named[0].credential.as_ref(), "aaaaaaaaaaaaaaaaaaaaaaaa");
}

#[test]
fn active_resolution_uses_custom_typed_plan_and_rejects_unknown_identity() {
    let anchored = DetectorSpec {
        id: "opaque-detector-id".into(),
        name: "Opaque detector".into(),
        service: "generic".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "opaque=([A-Za-z0-9]{24})".into(),
            group: Some(1),
            required_literals: Vec::new(),
            ..PatternSpec::default()
        }],
        keywords: vec!["opaque".into()],
        ..DetectorSpec::default()
    };
    let generic = keyhog_core::detector_spec_by_id("generic-secret")
        .expect("embedded generic owner")
        .clone();
    let scanner = CompiledScanner::compile(vec![anchored, generic]).expect("compile custom corpus");
    let credential = "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q";
    let resolved = scanner
        .try_resolve_matches(vec![
            raw_match("generic-secret", "generic", credential, 0.99),
            raw_match("opaque-detector-id", "generic", credential, 0.10),
        ])
        .expect("active identities resolve");
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].detector_id.as_ref(), "opaque-detector-id");

    let error = scanner
        .try_resolve_matches(vec![raw_match(
            "absent-detector",
            "generic",
            credential,
            0.99,
        )])
        .expect_err("unknown identity cannot inherit embedded policy");
    assert!(error.contains("absent from the active compiled detector plan"));
}

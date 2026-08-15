use super::protocol::{RequiredOption, Response};
use keyhog_core::{MatchLocation, RawMatch, SensitiveString, Severity};
use keyhog_scanner::telemetry::StaticRecoveryStatus;
use std::collections::BTreeMap;
use std::sync::Arc;

fn raw_match() -> RawMatch {
    RawMatch {
        detector_id: Arc::from("test-detector"),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: SensitiveString::from("protected-daemon-credential"),
        credential_hash: [9u8; 32].into(),
        companions: Default::default(),
        location: MatchLocation {
            source: Arc::from("daemon"),
            file_path: Some(Arc::from("fixture.txt")),
            line: Some(1),
            offset: 3,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.5),
        confidence: Some(0.9),
        evidence: keyhog_core::EvidenceVerdict::from_reason(
            keyhog_core::EvidenceReasonCode::VendorPattern,
        ),
    }
}

fn recovery_rejections() -> BTreeMap<String, u64> {
    BTreeMap::from([
        ("malformed_expression".to_string(), 3),
        ("unsupported_call".to_string(), 2),
    ])
}

fn response() -> Response {
    Response::ScanResults {
        path: Some("fixture.txt".into()),
        matches: vec![raw_match()],
        engine_example_suppressions: 0,
        dogfood_events: Vec::new(),
        static_recovery_rejections: recovery_rejections(),
        static_recovery_status: StaticRecoveryStatus {
            supported: 7,
            unsupported: 2,
            erroneous: 3,
        },
        dogfood_detail_events_dropped: 0,
        source_coverage_gaps: Default::default(),
        backend_recovery: RequiredOption::None,
        profile: RequiredOption::None,
    }
}

/// Regression: plaintext remains forbidden through public RawMatch serde while
/// the authenticated daemon DTO alone roundtrips it and rejects missing fields.
#[test]
fn daemon_private_wire_is_the_only_plaintext_serde_boundary() {
    assert!(serde_json::to_string(&raw_match()).is_err());

    let encoded = serde_json::to_value(response()).expect("serialize protected daemon response");
    assert_eq!(
        encoded["matches"][0]["credential"],
        "protected-daemon-credential"
    );
    assert_eq!(encoded["matches"][0]["evidence"]["tier"], "likely");
    assert_eq!(
        encoded["matches"][0]["evidence"]["reason_code"],
        "vendor-pattern"
    );
    let decoded: Response =
        serde_json::from_value(encoded.clone()).expect("deserialize protected daemon response");
    match decoded {
        Response::ScanResults {
            matches,
            static_recovery_rejections,
            static_recovery_status,
            ..
        } => {
            assert_eq!(matches.len(), 1);
            assert_eq!(
                matches[0].credential.as_str(),
                "protected-daemon-credential"
            );
            assert_eq!(
                matches[0].evidence,
                keyhog_core::EvidenceVerdict::from_reason(
                    keyhog_core::EvidenceReasonCode::VendorPattern,
                )
            );
            assert_eq!(static_recovery_rejections, recovery_rejections());
            assert_eq!(
                static_recovery_status,
                StaticRecoveryStatus {
                    supported: 7,
                    unsupported: 2,
                    erroneous: 3,
                }
            );
            assert_eq!(
                static_recovery_rejections.values().sum::<u64>(),
                static_recovery_status.unsupported + static_recovery_status.erroneous,
                "the versioned response must conserve every rejection reason"
            );
        }
        other => panic!("expected daemon scan results, got {other:?}"),
    }

    let mut missing_status = encoded.clone();
    missing_status
        .as_object_mut()
        .expect("response JSON object")
        .remove("static_recovery_status");
    assert!(serde_json::from_value::<Response>(missing_status).is_err());
    let mut missing_evidence = encoded.clone();
    missing_evidence["matches"][0]
        .as_object_mut()
        .expect("match JSON object")
        .remove("evidence");
    assert!(serde_json::from_value::<Response>(missing_evidence).is_err());

    let mut malformed = encoded;
    malformed["matches"][0]
        .as_object_mut()
        .expect("match JSON object")
        .remove("credential");
    assert!(serde_json::from_value::<Response>(malformed).is_err());
}

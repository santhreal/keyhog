//! Micro gate for `cli/daemon/frame.rs` and `cli/daemon/protocol.rs`.

use crate::daemon::frame;
use crate::daemon::protocol::{
    BackendRecoveryStatus, RecoveredInputRangeStatus, Request, RequiredOption, Response,
    SourceCoverageGaps, WarmBackendIdentity, WarmBackendStatus, WIRE_VERSION,
};
use keyhog_scanner::telemetry::StaticRecoveryStatus;
use std::collections::BTreeMap;
use tokio::io::AsyncWriteExt;

fn ready_warm_backend() -> WarmBackendStatus {
    WarmBackendStatus {
        ready: true,
        daemon_generation: "test-generation".into(),
        identity: WarmBackendIdentity {
            engine: "test-engine".into(),
            gpu_artifact: None,
            binary_sha256: "test-binary".into(),
            detector_rules_digest: "rules123".into(),
            config_digest: "test-config".into(),
        },
        required_backends: vec!["cpu-fallback".into()],
        initialized_backends: vec!["cpu-fallback".into()],
        reason: None,
        repair_command: None,
    }
}

#[tokio::test]
async fn daemon_wire_v10_hello_roundtrip_carries_mass_gpu_contract() {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);

    frame::write_request(&mut client, &Request::Hello)
        .await
        .expect("write Hello");
    let req = frame::read_request(&mut server)
        .await
        .expect("read request")
        .expect("Hello frame");
    assert!(matches!(req, Request::Hello));

    frame::write_response(
        &mut server,
        &Response::Hello {
            wire_version: WIRE_VERSION,
            keyhog_version: "test".into(),
            git_hash: "abc123".into(),
            detector_rules_digest: "rules123".into(),
            backend_policy: "cpu-fallback".into(),
            detector_count: 1,
            uptime_secs: 0,
            warm_backend: ready_warm_backend(),
            mass_service: true,
            mass_gpu_primary_required: true,
        },
    )
    .await
    .expect("write Hello response");
    let resp = frame::read_response(&mut client)
        .await
        .expect("read response")
        .expect("Hello response frame");
    match resp {
        Response::Hello {
            wire_version,
            mass_gpu_primary_required,
            ..
        } => {
            assert_eq!(wire_version, WIRE_VERSION);
            assert!(mass_gpu_primary_required);
        }
        other => panic!("expected Hello response, got {other:?}"),
    }
}

#[tokio::test]
async fn daemon_scan_text_roundtrip_carries_matches() {
    use keyhog_core::{MatchLocation, RawMatch, Severity};
    use std::sync::Arc;

    let (mut client, mut server) = tokio::io::duplex(256 * 1024);
    let sample = RawMatch {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Access Key"),
        service: Arc::from("aws"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from(concat!("AK", "IAQYLPMN5HFIQR7XYA")),
        credential_hash: [7u8; 32].into(),
        companions: Default::default(),
        location: MatchLocation {
            source: Arc::from("daemon"),
            file_path: Some(Arc::from("test.txt")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    };

    frame::write_request(
        &mut client,
        &Request::ScanText {
            path: Some("test.txt".into()),
            text: concat!("AK", "IAQYLPMN5HFIQR7XYA").into(),
            dogfood: false,
        },
    )
    .await
    .unwrap();
    let req = frame::read_request(&mut server).await.unwrap().unwrap();
    assert!(matches!(req, Request::ScanText { .. }));

    frame::write_response(
        &mut server,
        &Response::ScanResults {
            path: Some("test.txt".into()),
            matches: vec![sample],
            engine_example_suppressions: 0,
            dogfood_events: vec![],
            static_recovery_rejections: BTreeMap::new(),
            static_recovery_status: StaticRecoveryStatus::default(),
            dogfood_detail_events_dropped: 0,
            source_coverage_gaps: Default::default(),
            backend_recovery: RequiredOption::None,
        },
    )
    .await
    .unwrap();
    let resp = frame::read_response(&mut client).await.unwrap().unwrap();
    match resp {
        Response::ScanResults { matches, .. } => {
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].detector_id.as_ref(), "aws-access-key");
        }
        other => panic!("expected ScanResults, got {other:?}"),
    }
}

#[test]
fn daemon_wire_v8_requires_every_scan_result_integrity_field() {
    let complete = Response::ScanResults {
        path: None,
        matches: vec![],
        engine_example_suppressions: 0,
        dogfood_events: vec![],
        static_recovery_rejections: BTreeMap::new(),
        static_recovery_status: StaticRecoveryStatus::default(),
        dogfood_detail_events_dropped: 0,
        source_coverage_gaps: SourceCoverageGaps::default(),
        backend_recovery: RequiredOption::None,
    };
    let complete = serde_json::to_value(complete).expect("serialize complete response");

    for missing in [
        "engine_example_suppressions",
        "dogfood_events",
        "source_coverage_gaps",
        "static_recovery_rejections",
        "static_recovery_status",
        "dogfood_detail_events_dropped",
        "backend_recovery",
    ] {
        let mut incomplete = complete.clone();
        incomplete
            .as_object_mut()
            .expect("response object")
            .remove(missing);
        let error = serde_json::from_value::<Response>(incomplete)
            .expect_err("wire-v8 ScanResults must reject omitted integrity fields");
        assert!(
            error.to_string().contains(missing),
            "missing {missing} must be named in the frame error: {error}"
        );
    }

    let mut incomplete = complete;
    incomplete["source_coverage_gaps"]
        .as_object_mut()
        .expect("coverage object")
        .remove("over_max_size");
    let error = serde_json::from_value::<Response>(incomplete)
        .expect_err("wire-v8 must reject incomplete source coverage");
    assert!(error.to_string().contains("over_max_size"));
}

#[test]
fn daemon_scan_results_source_coverage_gaps_roundtrip_exactly() {
    let response = Response::ScanResults {
        path: None,
        matches: vec![],
        engine_example_suppressions: 0,
        dogfood_events: vec![],
        static_recovery_rejections: BTreeMap::from([("json_base64".into(), 3)]),
        static_recovery_status: StaticRecoveryStatus {
            supported: 5,
            unsupported: 0,
            erroneous: 3,
        },
        dogfood_detail_events_dropped: 7,
        source_coverage_gaps: SourceCoverageGaps {
            binary: 1,
            ..Default::default()
        },
        backend_recovery: RequiredOption::Some(BackendRecoveryStatus {
            failed_backend: "gpu-cuda-region-presence".into(),
            recovery_backend: "cpu-fallback".into(),
            recovered_ranges: vec![RecoveredInputRangeStatus {
                chunk_index: 2,
                byte_start: 64,
                byte_end: 96,
            }],
            recovered_chunks: 1,
            recovered_bytes: 32,
            reason: "injected dispatch fault".into(),
        }),
    };
    let encoded = serde_json::to_string(&response).expect("serialize scan results");
    let decoded: Response = serde_json::from_str(&encoded).expect("deserialize scan results");
    match decoded {
        Response::ScanResults {
            source_coverage_gaps,
            static_recovery_rejections,
            static_recovery_status,
            dogfood_detail_events_dropped,
            backend_recovery,
            ..
        } => {
            assert_eq!(source_coverage_gaps.binary, 1);
            assert_eq!(source_coverage_gaps.total(), 1);
            // KH-1368: WARN-class binary alone must not trip FAIL incomplete.
            assert!(source_coverage_gaps.fail_class_empty());
            assert_eq!(
                SourceCoverageGaps {
                    unreadable: 2,
                    binary: 9,
                    ..Default::default()
                }
                .fail_class_total(),
                2
            );
            assert_eq!(static_recovery_rejections["json_base64"], 3);
            assert_eq!(
                static_recovery_status,
                StaticRecoveryStatus {
                    supported: 5,
                    unsupported: 0,
                    erroneous: 3,
                }
            );
            assert_eq!(dogfood_detail_events_dropped, 7);
            let recovery = backend_recovery.expect("recovery status");
            assert_eq!(recovery.recovered_bytes, 32);
            assert_eq!(
                recovery.recovered_ranges,
                vec![RecoveredInputRangeStatus {
                    chunk_index: 2,
                    byte_start: 64,
                    byte_end: 96,
                }]
            );
        }
        other => panic!("expected ScanResults, got {other:?}"),
    }
}

#[tokio::test]
async fn daemon_frame_rejects_oversized_length_prefix() {
    use keyhog::daemon::protocol::MAX_FRAME_BYTES;

    let (mut client, mut server) = tokio::io::duplex(256);
    let bogus_len = (MAX_FRAME_BYTES + 1).to_be_bytes();
    client.write_all(&bogus_len).await.unwrap();
    let err = frame::read_request(&mut server).await.unwrap_err();
    assert!(
        err.to_string().contains("exceeds"),
        "oversized frame must be rejected; got {err}"
    );
}

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
            profile: false,
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
            profile: RequiredOption::None,
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
        profile: RequiredOption::None,
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
        "profile",
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
        profile: RequiredOption::None,
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

/// Locks the v14 bump: daemon-local incremental cache state changes the
/// MassFilesystemBegin frame, so older peers must fail at Hello.
#[test]
fn daemon_wire_version_is_v14_with_mass_incremental_state() {
    assert_eq!(WIRE_VERSION, 14);
}

#[tokio::test]
async fn daemon_wire_v14_mass_incremental_cache_roundtrips() {
    let request = Request::MassFilesystemBegin {
        root: "/workspace".into(),
        max_file_size: 1024,
        ignore_paths: vec!["target".into()],
        respect_default_excludes: true,
        reader_threads: Some(2),
        incremental_cache: Some("/cache/keyhog/merkle.idx".into()),
    };
    let encoded = serde_json::to_string(&request).expect("serialize request");
    let decoded: Request = serde_json::from_str(&encoded).expect("deserialize request");
    let reencoded = serde_json::to_string(&decoded).expect("re-serialize request");
    assert_eq!(
        reencoded, encoded,
        "the exact incremental cache identity must survive the wire boundary"
    );
}

/// The v12 `profile` opt-in must survive the frame round-trip verbatim on
/// every request kind that carries it; a dropped flag would silently turn
/// off per-request profiling on the daemon route.
#[tokio::test]
async fn daemon_wire_v12_profile_flag_roundtrips_on_scan_requests() {
    let requests = [
        Request::ScanText {
            path: Some("stdin".into()),
            text: "payload".into(),
            dogfood: false,
            profile: true,
        },
        Request::ScanPath {
            path: "src/main.rs".into(),
            working_dir: Some("/tmp/project".into()),
            dogfood: false,
            profile: true,
        },
        Request::MassBegin {
            dogfood: true,
            profile: true,
        },
        Request::ScanText {
            path: None,
            text: "unprofiled".into(),
            dogfood: false,
            profile: false,
        },
    ];
    for request in requests {
        let encoded = serde_json::to_string(&request).expect("serialize request");
        let decoded: Request = serde_json::from_str(&encoded).expect("deserialize request");
        let (expected, actual) = match (&request, &decoded) {
            (
                Request::ScanText {
                    profile: expected, ..
                },
                Request::ScanText {
                    profile: actual, ..
                },
            )
            | (
                Request::ScanPath {
                    profile: expected, ..
                },
                Request::ScanPath {
                    profile: actual, ..
                },
            )
            | (
                Request::MassBegin {
                    profile: expected, ..
                },
                Request::MassBegin {
                    profile: actual, ..
                },
            ) => (expected, actual),
            (sent, got) => panic!("request kind changed across the wire: {sent:?} -> {got:?}"),
        };
        assert_eq!(expected, actual, "profile flag must round-trip exactly");
    }
}

/// A profiled v12 `ScanResults` must carry the exact request profile payload
/// (id, wall time, per-stage aggregates, loss counts) across the frame
/// boundary, and an unprofiled response must serialize `profile` as an
/// explicit null that deserializes back to `None`, never to a fabricated
/// zero-valued profile.
#[tokio::test]
async fn daemon_wire_v12_scan_results_roundtrips_request_profile() {
    use crate::daemon::protocol::{ProfileStageMeasurement, RequestProfile};

    let profile = RequestProfile {
        request_id: "4242-after-00000001-00000000-0000000000000000".into(),
        wall_time_ns: 1_523_987,
        stages: vec![
            ProfileStageMeasurement {
                stage: "phase1-triggers".into(),
                calls: 3,
                elapsed_ns: 981_114,
            },
            ProfileStageMeasurement {
                stage: "entropy".into(),
                calls: 1,
                elapsed_ns: 12_500,
            },
        ],
        dropped_span_events: 2,
        dropped_point_events: 0,
        dropped_annotations: 1,
        sampled_out_events: 5,
    };
    let response = Response::ScanResults {
        path: None,
        matches: vec![],
        engine_example_suppressions: 0,
        dogfood_events: vec![],
        static_recovery_rejections: BTreeMap::new(),
        static_recovery_status: StaticRecoveryStatus::default(),
        dogfood_detail_events_dropped: 0,
        source_coverage_gaps: SourceCoverageGaps::default(),
        backend_recovery: RequiredOption::None,
        profile: RequiredOption::Some(profile.clone()),
    };

    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    frame::write_response(&mut server, &response)
        .await
        .expect("write profiled ScanResults");
    let decoded = frame::read_response(&mut client)
        .await
        .expect("read response")
        .expect("ScanResults frame");
    match decoded {
        Response::ScanResults {
            profile: decoded, ..
        } => {
            let decoded = decoded.expect("request profile");
            assert_eq!(decoded, profile, "profile payload must round-trip exactly");
        }
        other => panic!("expected ScanResults, got {other:?}"),
    }

    let unprofiled = Response::ScanResults {
        path: None,
        matches: vec![],
        engine_example_suppressions: 0,
        dogfood_events: vec![],
        static_recovery_rejections: BTreeMap::new(),
        static_recovery_status: StaticRecoveryStatus::default(),
        dogfood_detail_events_dropped: 0,
        source_coverage_gaps: SourceCoverageGaps::default(),
        backend_recovery: RequiredOption::None,
        profile: RequiredOption::None,
    };
    let encoded = serde_json::to_value(&unprofiled).expect("serialize unprofiled response");
    assert_eq!(
        encoded["profile"],
        serde_json::Value::Null,
        "unprofiled ScanResults must carry an explicit null profile field"
    );
    let decoded: Response = serde_json::from_value(encoded).expect("deserialize unprofiled");
    match decoded {
        Response::ScanResults { profile, .. } => {
            assert!(profile.is_none(), "null profile must decode to None");
        }
        other => panic!("expected ScanResults, got {other:?}"),
    }
}

/// The v13 `GuardList` request and `GuardListResult` response must round-trip
/// through the frame boundary with all root entries preserved.
#[tokio::test]
async fn daemon_wire_v13_guard_list_roundtrips() {
    use crate::daemon::protocol::{GuardListEntry, Request, Response};

    let (mut client, mut server) = tokio::io::duplex(64 * 1024);

    frame::write_request(&mut client, &Request::GuardList)
        .await
        .expect("write GuardList");
    let req = frame::read_request(&mut server)
        .await
        .expect("read request")
        .expect("GuardList frame");
    assert!(matches!(req, Request::GuardList));

    let response = Response::GuardListResult {
        roots: vec![
            GuardListEntry {
                root: "/work/project".to_string(),
                mode: "repo".to_string(),
                state: "current".to_string(),
                terminal_sequence: 42,
            },
            GuardListEntry {
                root: "/srv/data".to_string(),
                mode: "filesystem".to_string(),
                state: "indexing".to_string(),
                terminal_sequence: 0,
            },
        ],
    };
    frame::write_response(&mut server, &response)
        .await
        .expect("write GuardListResult");
    let resp = frame::read_response(&mut client)
        .await
        .expect("read response")
        .expect("GuardListResult frame");
    match resp {
        Response::GuardListResult { roots } => {
            assert_eq!(roots.len(), 2);
            assert_eq!(roots[0].root, "/work/project");
            assert_eq!(roots[0].mode, "repo");
            assert_eq!(roots[0].state, "current");
            assert_eq!(roots[0].terminal_sequence, 42);
            assert_eq!(roots[1].root, "/srv/data");
            assert_eq!(roots[1].mode, "filesystem");
            assert_eq!(roots[1].state, "indexing");
            assert_eq!(roots[1].terminal_sequence, 0);
        }
        other => panic!("expected GuardListResult, got {other:?}"),
    }
}

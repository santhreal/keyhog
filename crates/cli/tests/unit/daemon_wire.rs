//! Micro gate for `cli/daemon/frame.rs` and `cli/daemon/protocol.rs`.

use keyhog::daemon::frame;
use keyhog::daemon::protocol::{Request, Response, SourceCoverageGaps, WIRE_VERSION};
use std::collections::BTreeMap;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn daemon_wire_v4_hello_roundtrip() {
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
            detector_count: 1,
            uptime_secs: 0,
        },
    )
    .await
    .expect("write Hello response");
    let resp = frame::read_response(&mut client)
        .await
        .expect("read response")
        .expect("Hello response frame");
    match resp {
        Response::Hello { wire_version, .. } => assert_eq!(wire_version, WIRE_VERSION),
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
            dogfood_detail_events_dropped: 0,
            source_coverage_gaps: Default::default(),
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
fn daemon_wire_v4_requires_every_scan_result_integrity_field() {
    let complete = Response::ScanResults {
        path: None,
        matches: vec![],
        engine_example_suppressions: 0,
        dogfood_events: vec![],
        static_recovery_rejections: BTreeMap::new(),
        dogfood_detail_events_dropped: 0,
        source_coverage_gaps: SourceCoverageGaps::default(),
    };
    let complete = serde_json::to_value(complete).expect("serialize complete response");

    for missing in [
        "engine_example_suppressions",
        "dogfood_events",
        "source_coverage_gaps",
        "static_recovery_rejections",
        "dogfood_detail_events_dropped",
    ] {
        let mut incomplete = complete.clone();
        incomplete
            .as_object_mut()
            .expect("response object")
            .remove(missing);
        let error = serde_json::from_value::<Response>(incomplete)
            .expect_err("wire-v4 ScanResults must reject omitted integrity fields");
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
        .expect_err("wire-v4 must reject incomplete source coverage");
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
        dogfood_detail_events_dropped: 7,
        source_coverage_gaps: SourceCoverageGaps {
            binary: 1,
            ..Default::default()
        },
    };
    let encoded = serde_json::to_string(&response).expect("serialize scan results");
    let decoded: Response = serde_json::from_str(&encoded).expect("deserialize scan results");
    match decoded {
        Response::ScanResults {
            source_coverage_gaps,
            static_recovery_rejections,
            dogfood_detail_events_dropped,
            ..
        } => {
            assert_eq!(source_coverage_gaps.binary, 1);
            assert_eq!(source_coverage_gaps.total(), 1);
            assert_eq!(static_recovery_rejections["json_base64"], 3);
            assert_eq!(dogfood_detail_events_dropped, 7);
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

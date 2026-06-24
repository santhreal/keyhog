//! Micro gate for `cli/daemon/frame.rs` and `cli/daemon/protocol.rs`.

use keyhog::daemon::frame;
use keyhog::daemon::protocol::{Request, Response, SourceCoverageGaps, WIRE_VERSION};
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn daemon_wire_v2_hello_roundtrip() {
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
fn daemon_scan_results_source_coverage_gaps_are_defaulted_and_serialized() {
    let legacy: Response =
        serde_json::from_str(r#"{"kind":"scan_results","path":null,"matches":[]}"#)
            .expect("legacy scan results deserialize");
    match legacy {
        Response::ScanResults {
            source_coverage_gaps,
            ..
        } => assert!(source_coverage_gaps.is_empty()),
        other => panic!("expected legacy ScanResults, got {other:?}"),
    }

    let response = Response::ScanResults {
        path: None,
        matches: vec![],
        engine_example_suppressions: 0,
        dogfood_events: vec![],
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
            ..
        } => {
            assert_eq!(source_coverage_gaps.binary, 1);
            assert_eq!(source_coverage_gaps.total(), 1);
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

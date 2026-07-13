use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    AuthSpec, DedupedMatch, DetectorSpec, MatchLocation, MetadataSpec, Severity, SuccessSpec,
    VerificationResult, VerifySpec,
};
use keyhog_verifier::{VerificationEngine, VerifyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn malformed_json_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = r#"{"valid":true"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://127.0.0.1:{port}/verify")
}

async fn unauthorized_text_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = "invalid credential";
                let response = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://127.0.0.1:{port}/verify")
}

fn detector_for(url: String) -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "json-contract".into(),
        name: "JSON contract".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            service: "test".into(),
            url: Some(url),
            method: None,
            auth: Some(AuthSpec::None {}),
            headers: vec![],
            body: None,
            success: Some(SuccessSpec {
                status: Some(200),
                json_path: Some("$.valid".into()),
                equals: Some("true".into()),
                ..Default::default()
            }),
            metadata: vec![],
            timeout_ms: None,
            steps: vec![],
            allowed_domains: vec!["127.0.0.1".into()],
            oob: None,
        }),
        ..Default::default()
    }
}

fn group() -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from("json-contract"),
        detector_name: Arc::from("JSON contract"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from("secret"),
        credential_hash: [0u8; 32].into(),
        primary_location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from("fixture.txt")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: vec![],
        companions: HashMap::new(),
        confidence: Some(1.0),
    }
}

#[tokio::test]
async fn malformed_success_json_returns_error_not_dead() {
    let engine = VerificationEngine::new(
        &[detector_for(malformed_json_server().await)],
        VerifyConfig {
            danger_allow_private_ips: true,
            danger_allow_http: true,
            ..Default::default()
        },
    )
    .unwrap();

    let findings = engine.verify_all(vec![group()]).await;
    assert_eq!(
        findings.len(),
        1,
        "one verified group should return one finding"
    );

    match &findings[0].verification {
        VerificationResult::Error(message) => assert!(
            message.contains("response body is not valid JSON for success selector `$.valid`"),
            "error must explain the malformed success JSON contract, got {message:?}"
        ),
        other => panic!("malformed success JSON must not become {other:?}"),
    }
}

#[tokio::test]
async fn rejected_non_json_response_remains_dead_when_metadata_is_configured() {
    let mut detector = detector_for(unauthorized_text_server().await);
    detector.verify.as_mut().unwrap().metadata = vec![MetadataSpec {
        name: "account".into(),
        json_path: "$.account".into(),
    }];
    let engine = VerificationEngine::new(
        &[detector],
        VerifyConfig {
            danger_allow_private_ips: true,
            danger_allow_http: true,
            ..Default::default()
        },
    )
    .unwrap();

    let findings = engine.verify_all(vec![group()]).await;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].verification, VerificationResult::Dead);
    assert!(findings[0].metadata.is_empty());
}

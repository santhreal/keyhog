use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use keyhog_core::{
    AuthSpec, DedupedMatch, DetectorSpec, HttpMethod, MatchLocation, OobPolicy, OobProtocol,
    OobSpec, Severity, StepSpec, SuccessSpec, VerificationResult, VerifySpec,
};
use keyhog_verifier::{VerificationEngine, VerifyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn counting_server(requests: Arc<AtomicUsize>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let requests = requests.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                requests.fetch_add(1, Ordering::SeqCst);
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    .await;
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn group_for(detector_id: &str) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_id),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from("secret-value"),
        credential_hash: [0u8; 32],
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

fn oob_spec() -> OobSpec {
    OobSpec {
        protocol: OobProtocol::Http,
        timeout_secs: Some(1),
        policy: OobPolicy::OobAndHttp,
    }
}

fn engine_for(spec: DetectorSpec) -> VerificationEngine {
    VerificationEngine::new(
        &[spec],
        VerifyConfig {
            danger_allow_private_ips: true,
            danger_allow_http: true,
            ..Default::default()
        },
    )
    .unwrap()
}

#[tokio::test]
async fn oob_required_without_session_errors_before_http_probe() {
    let requests = Arc::new(AtomicUsize::new(0));
    let base = counting_server(requests.clone()).await;
    let detector = DetectorSpec {
        id: "oob-no-session".into(),
        name: "OOB no session".into(),
        service: "test".into(),
        severity: Severity::Critical,
        keywords: vec![],
        patterns: vec![],
        companions: vec![],
        tests: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            service: "test".into(),
            method: Some(HttpMethod::Post),
            url: Some(format!("{base}/probe")),
            auth: Some(AuthSpec::None),
            headers: vec![],
            body: Some(r#"{"callback":"{{interactsh.url}}"}"#.into()),
            success: Some(SuccessSpec {
                status: Some(200),
                ..Default::default()
            }),
            metadata: vec![],
            timeout_ms: None,
            steps: vec![],
            allowed_domains: vec!["127.0.0.1".into()],
            oob: Some(oob_spec()),
        }),
        ..Default::default()
    };

    let findings = engine_for(detector)
        .verify_all(vec![group_for("oob-no-session")])
        .await;

    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        findings[0].metadata.get("oob_disabled").map(String::as_str),
        Some("no active OOB session")
    );
    match &findings[0].verification {
        VerificationResult::Error(message) => assert!(
            message.contains("OOB verification required by detector")
                && message.contains("--verify-oob"),
            "OOB-required verifier must fail loudly with operator fix text; got {message:?}"
        ),
        other => panic!("expected OOB-required Error, got {other:?}"),
    }
}

#[tokio::test]
async fn multi_step_oob_errors_before_any_step_request() {
    let requests = Arc::new(AtomicUsize::new(0));
    let base = counting_server(requests.clone()).await;
    let detector = DetectorSpec {
        id: "oob-multi-step".into(),
        name: "OOB multi step".into(),
        service: "test".into(),
        severity: Severity::Critical,
        keywords: vec![],
        patterns: vec![],
        companions: vec![],
        tests: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            service: "test".into(),
            method: None,
            url: None,
            auth: None,
            headers: vec![],
            body: None,
            success: None,
            metadata: vec![],
            timeout_ms: None,
            steps: vec![StepSpec {
                name: "probe".into(),
                method: HttpMethod::Post,
                url: format!("{base}/step"),
                auth: AuthSpec::None,
                headers: vec![],
                body: Some(r#"{"callback":"{{interactsh.url}}"}"#.into()),
                success: SuccessSpec {
                    status: Some(200),
                    ..Default::default()
                },
                extract: vec![],
            }],
            allowed_domains: vec!["127.0.0.1".into()],
            oob: Some(oob_spec()),
        }),
        ..Default::default()
    };

    let findings = engine_for(detector)
        .verify_all(vec![group_for("oob-multi-step")])
        .await;

    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        findings[0].metadata.get("oob_disabled").map(String::as_str),
        Some("multi-step OOB verification has no per-step callback binding")
    );
    match &findings[0].verification {
        VerificationResult::Error(message) => assert!(
            message.contains("multi-step verify specs cannot use [detector.verify.oob]")
                && message.contains("concrete request step"),
            "multi-step OOB must fail loudly with the contract reason; got {message:?}"
        ),
        other => panic!("expected multi-step OOB Error, got {other:?}"),
    }
}

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use keyhog_core::{
    AuthSpec, DedupedMatch, DetectorSpec, HttpMethod, MatchLocation, Severity, StepSpec,
    SuccessSpec, VerificationResult, VerifySpec,
};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use keyhog_verifier::{VerificationEngine, VerifyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn transient_then_live_server(requests: Arc<AtomicUsize>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let requests = requests.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let request_number = requests.fetch_add(1, Ordering::SeqCst);
                let response = if request_number == 0 {
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nretry"
                        .as_slice()
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".as_slice()
                };
                let _ = stream.write_all(response).await;
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn group_for(detector_id: &str) -> DedupedMatch {
    group_for_credential(detector_id, "secret-value")
}

fn group_for_credential(detector_id: &str, credential: &str) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_id),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from(credential),
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

#[test]
fn multi_step_non_aws_auth_uses_verify_service_rate_bucket() {
    let spec = VerifySpec {
        service: "service-a".into(),
        ..Default::default()
    };
    let auth = AuthSpec::None;

    assert_eq!(
        TestApi.multi_step_rate_limit_service_name(&spec, &auth),
        "service-a",
        "non-AWS multi-step verification must not collapse into an unknown shared limiter bucket"
    );
}

#[test]
fn multi_step_aws_auth_uses_sigv4_service_rate_bucket() {
    let spec = VerifySpec {
        service: "aws-detector-family".into(),
        ..Default::default()
    };
    let auth = AuthSpec::AwsV4 {
        access_key: "{{match}}".into(),
        secret_key: "{{companion.secret}}".into(),
        region: "us-east-1".into(),
        service: "sts".into(),
        session_token: None,
    };

    assert_eq!(
        TestApi.multi_step_rate_limit_service_name(&spec, &auth),
        "sts",
        "SigV4 multi-step verification must rate-limit by the signed AWS service"
    );
}

#[tokio::test]
async fn multi_step_500_retries_then_live() {
    let requests = Arc::new(AtomicUsize::new(0));
    let base = transient_then_live_server(requests.clone()).await;
    let detector = DetectorSpec {
        id: "multi-step-retry".into(),
        name: "Multi-step retry".into(),
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
                method: HttpMethod::Get,
                url: format!("{base}/step"),
                auth: AuthSpec::None,
                headers: vec![],
                body: None,
                success: SuccessSpec {
                    status: Some(200),
                    ..Default::default()
                },
                extract: vec![],
            }],
            allowed_domains: vec!["127.0.0.1".into()],
            oob: None,
        }),
        ..Default::default()
    };

    let findings = engine_for(detector)
        .verify_all(vec![group_for("multi-step-retry")])
        .await;

    assert_eq!(
        requests.load(Ordering::SeqCst),
        2,
        "a transient multi-step response must be retried before classifying the credential"
    );
    assert_eq!(findings[0].verification, VerificationResult::Live);
}

#[tokio::test]
async fn multi_step_empty_credential_is_unverifiable_without_network() {
    let requests = Arc::new(AtomicUsize::new(0));
    let base = transient_then_live_server(requests.clone()).await;
    let detector = DetectorSpec {
        id: "multi-step-empty-credential".into(),
        name: "Multi-step empty credential".into(),
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
                method: HttpMethod::Get,
                url: format!("{base}/step"),
                auth: AuthSpec::None,
                headers: vec![],
                body: None,
                success: SuccessSpec {
                    status: Some(200),
                    ..Default::default()
                },
                extract: vec![],
            }],
            allowed_domains: vec!["127.0.0.1".into()],
            oob: None,
        }),
        ..Default::default()
    };

    let findings = engine_for(detector)
        .verify_all(vec![group_for_credential(
            "multi-step-empty-credential",
            "",
        )])
        .await;

    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "empty credentials must be classified before multi-step verification sends a request"
    );
    assert_eq!(
        findings[0].verification,
        VerificationResult::Unverifiable,
        "empty credentials are an unverifiable input, not a missing-template/auth error"
    );
}

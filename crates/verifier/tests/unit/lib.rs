use keyhog_core::{dedup_matches, DedupScope, DetectorSpec, MatchLocation, RawMatch, Severity};
use keyhog_verifier::{VerificationEngine, VerifyConfig};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_verify_all_logic() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let requests_clone = requests.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let count = requests_clone.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                count.fetch_add(1, Ordering::SeqCst);
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    .await;
            });
        }
    });

    let detector = DetectorSpec {
        id: "test".into(),
        name: "Test".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![],
        companions: vec![],
        verify: Some(keyhog_core::VerifySpec {
            service: "test".into(),
            method: Some(keyhog_core::HttpMethod::Get),
            url: Some(format!("http://127.0.0.1:{}/verify", addr.port())),
            auth: Some(keyhog_core::AuthSpec::None),
            headers: vec![],
            body: None,
            success: Some(keyhog_core::SuccessSpec {
                status: Some(200),
                ..Default::default()
            }),
            metadata: vec![],
            timeout_ms: None,
            steps: vec![],
            // Test mock HTTP server binds 127.0.0.1; the new domain
            // allowlist (kimi-wave1 4.1) requires the test to declare
            // its target. Production paths use the per-service builtin
            // map and never need this.
            allowed_domains: vec!["127.0.0.1".into()],
            oob: None,
        }),
        keywords: vec![],
        ..Default::default()
    };

    let mut config = VerifyConfig::default();
    config.danger_allow_private_ips = true;
    // Mock HTTP server is bound to 127.0.0.1, not behind TLS — opt into
    // plaintext HTTP for the test. Production paths default to HTTPS-only.
    config.danger_allow_http = true;

    let engine = VerificationEngine::new(&[detector], config).unwrap();
    let m = RawMatch {
        detector_id: "test".into(),
        detector_name: "Test".into(),
        service: "test".into(),
        severity: Severity::High,
        credential: "same-credential".into(),
        credential_hash: "hash".into(),
        companions: HashMap::new(),
        location: MatchLocation {
            source: "fs".into(),
            file_path: Some("a.txt".into()),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.9),
    };

    let group = dedup_matches(vec![m], &DedupScope::Credential)
        .pop()
        .unwrap();
    let findings = engine.verify_all(vec![group]).await;
    assert_eq!(findings.len(), 1);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

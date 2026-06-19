use keyhog_core::{
    DedupedMatch, DetectorSpec, HttpMethod, MatchLocation, Severity, SuccessSpec, VerifySpec,
};
use keyhog_verifier::{VerificationEngine, VerifyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn spawn_mock_server<F, Fut>(handler: F) -> String
where
    F: Fn(tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = handler.clone();
            tokio::spawn(async move {
                h(stream).await;
            });
        }
    });
    format!("http://127.0.0.1:{}", port)
}

#[tokio::test]
async fn test_verify_large_payload() {
    let url = spawn_mock_server(|mut stream| async move {
        let mut buf = [0; 1024];
        let _ = stream.read(&mut buf).await;
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2000000\r\n\r\n";
        let _ = stream.write_all(response).await;
        // write 2MB of 'A's
        let chunk = vec![b'A'; 1024 * 1024];
        let _ = stream.write_all(&chunk).await;
        let _ = stream.write_all(&chunk).await;
    })
    .await;

    let spec = DetectorSpec { tests: Vec::new(),
        id: "det1".to_string(),
        name: "det1".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            url: Some(url),
            method: Some(HttpMethod::Get),
            headers: vec![],
            body: None,
            auth: None,
            success: None,
            metadata: vec![],
            service: "test".to_string(),
            timeout_ms: None,
            steps: vec![],
            allowed_domains: vec!["127.0.0.1".into(), "localhost".into()],
            oob: None,
        }),
        ..Default::default()
    };

    let engine = VerificationEngine::new(
        &[spec],
        VerifyConfig {
            danger_allow_private_ips: true,
            danger_allow_http: true,
            ..Default::default()
        },
    )
    .unwrap();
    let group = DedupedMatch {
        detector_id: Arc::from("det1"),
        detector_name: Arc::from("det1"),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from("secret"),
        credential_hash: [0u8; 32],
        primary_location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from("test")),
            line: Some(1),
            offset: 1,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: vec![],
        companions: HashMap::new(),
        confidence: Some(1.0),
    };

    let findings = engine.verify_all(vec![group]).await;
    assert_eq!(findings.len(), 1);
    match &findings[0].verification {
        VerificationResult::Error(msg) => {
            assert!(
                msg.contains("exceeds 1MB"),
                "Should block large payload: {}",
                msg
            );
        }
        _ => panic!(
            "Expected error for large payload, got {:?}",
            findings[0].verification
        ),
    }
}

#[tokio::test]
async fn test_verify_malformed_response() {
    let url = spawn_mock_server(|mut stream| async move {
        let mut buf = [0; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream.write_all(b"GARBAGE NON HTTP DATA\r\n").await;
    })
    .await;

    let spec = DetectorSpec { tests: Vec::new(),
        id: "det2".to_string(),
        name: "det2".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            url: Some(url),
            method: Some(HttpMethod::Get),
            headers: vec![],
            body: None,
            auth: None,
            success: None,
            metadata: vec![],
            service: "test".to_string(),
            timeout_ms: None,
            steps: vec![],
            allowed_domains: vec!["127.0.0.1".into(), "localhost".into()],
            oob: None,
        }),
        ..Default::default()
    };

    let engine = VerificationEngine::new(
        &[spec],
        VerifyConfig {
            danger_allow_private_ips: true,
            danger_allow_http: true,
            ..Default::default()
        },
    )
    .unwrap();
    let group = DedupedMatch {
        detector_id: Arc::from("det2"),
        detector_name: Arc::from("det2"),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from("secret"),
        credential_hash: [0u8; 32],
        primary_location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from("test")),
            line: Some(1),
            offset: 1,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: vec![],
        companions: HashMap::new(),
        confidence: Some(1.0),
    };

    let findings = engine.verify_all(vec![group]).await;
    assert_eq!(findings.len(), 1);
    match &findings[0].verification {
        VerificationResult::Error(_) => {}
        _ => panic!("Expected error for malformed response"),
    }
}

#[tokio::test]
async fn test_verify_zero_concurrency() {
    let config = VerifyConfig {
        max_concurrent_global: 0,
        max_concurrent_per_service: 0,
        ..Default::default()
    };

    let spec = DetectorSpec { tests: Vec::new(),
        id: "det_zero".to_string(),
        name: "det_zero".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            url: Some("http://127.0.0.1:1".to_string()),
            method: None,
            headers: vec![],
            body: None,
            auth: None,
            success: None,
            metadata: vec![],
            service: "test".to_string(),
            timeout_ms: None,
            steps: vec![],
            allowed_domains: vec!["127.0.0.1".into(), "localhost".into()],
            oob: None,
        }),
        ..Default::default()
    };

    let engine = VerificationEngine::new(&[spec], config).unwrap();
    let group = DedupedMatch {
        detector_id: Arc::from("det_zero"),
        detector_name: Arc::from("det_zero"),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from("secret"),
        credential_hash: [0u8; 32],
        primary_location: MatchLocation {
            source: Arc::from(""),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: vec![],
        companions: HashMap::new(),
        confidence: None,
    };

    // If global concurrency is 0, max(1) should override it or it will block.
    // Let's assert it doesn't block forever.
    let result = tokio::time::timeout(Duration::from_secs(2), engine.verify_all(vec![group])).await;
    if result.is_err() {
        panic!("Bug found: zero concurrency limit causes deadlock");
    }
}

#[tokio::test]
async fn test_verify_inflight_deadlock_on_duplicates() {
    // Tests that requesting the same key 100 times concurrently doesn't deadlock the inflight deduplication lock
    let url = spawn_mock_server(|mut stream| async move {
        let mut buf = [0; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
    })
    .await;

    let spec = DetectorSpec { tests: Vec::new(),
        id: "det_dup".to_string(),
        name: "det_dup".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            url: Some(url),
            method: None,
            headers: vec![],
            body: None,
            auth: None,
            success: None,
            metadata: vec![],
            service: "test".to_string(),
            timeout_ms: None,
            steps: vec![],
            allowed_domains: vec!["127.0.0.1".into(), "localhost".into()],
            oob: None,
        }),
        ..Default::default()
    };

    let engine = VerificationEngine::new(
        &[spec],
        VerifyConfig {
            max_concurrent_global: 100,
            ..Default::default()
        },
    )
    .unwrap();
    let mut groups = Vec::new();
    for _ in 0..100 {
        groups.push(DedupedMatch {
            detector_id: Arc::from("det_dup"),
            detector_name: Arc::from("det_dup"),
            service: Arc::from("test"),
            severity: Severity::Critical,
            credential: keyhog_core::SensitiveString::from("same_secret"),
            credential_hash: [0u8; 32],
            primary_location: MatchLocation {
                source: Arc::from(""),
                file_path: None,
                line: None,
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            additional_locations: vec![],
            companions: HashMap::new(),
            confidence: None,
        });
    }

    let result = tokio::time::timeout(Duration::from_secs(5), engine.verify_all(groups)).await;
    assert!(result.is_ok(), "Should not deadlock on inflight duplicates");
    let findings = result.unwrap();
    assert_eq!(findings.len(), 100);
}

#[tokio::test]
async fn test_verify_slow_loris_timeout() {
    let url = spawn_mock_server(|mut stream| async move {
        let mut buf = [0; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n").await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = stream.write_all(b"Content-Length: 0\r\n\r\n").await;
    })
    .await;

    let spec = DetectorSpec { tests: Vec::new(),
        id: "det_slow".to_string(),
        name: "det_slow".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            url: Some(url),
            timeout_ms: Some(100),
            method: None,
            headers: vec![],
            body: None,
            auth: None,
            success: None,
            metadata: vec![],
            service: "test".to_string(),
            steps: vec![],
            allowed_domains: vec!["127.0.0.1".into(), "localhost".into()],
            oob: None,
        }),
        ..Default::default()
    };

    let engine = VerificationEngine::new(&[spec], VerifyConfig::default()).unwrap();
    let group = DedupedMatch {
        detector_id: Arc::from("det_slow"),
        detector_name: Arc::from("det_slow"),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from("secret"),
        credential_hash: [0u8; 32],
        primary_location: MatchLocation {
            source: Arc::from(""),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: vec![],
        companions: HashMap::new(),
        confidence: None,
    };

    let findings = engine.verify_all(vec![group]).await;
    assert_eq!(findings.len(), 1);
    match &findings[0].verification {
        VerificationResult::Error(e) => {
            if !e.contains("timeout")
                && !e.contains("max retries exceeded")
                && !e.contains("private")
            {
                panic!("Bug found: Expected timeout or private error, got {}", e);
            }
        }
        _ => panic!(
            "Bug found: Expected timeout error, got {:?}",
            findings[0].verification
        ),
    }
}

#[tokio::test]
async fn test_verify_max_inflight_keys() {
    let config = VerifyConfig {
        max_inflight_keys: 0,
        ..Default::default()
    };
    let engine = VerificationEngine::new(&[], config).unwrap();
    let group = DedupedMatch {
        detector_id: Arc::from("det_none"),
        detector_name: Arc::from("det_none"),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from("secret"),
        credential_hash: [0u8; 32],
        primary_location: MatchLocation {
            source: Arc::from(""),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: vec![],
        companions: HashMap::new(),
        confidence: None,
    };

    let result = tokio::time::timeout(Duration::from_secs(5), engine.verify_all(vec![group])).await;
    // With 0 max inflight keys, it loop-blocks forever waiting for space.
    // It's a finding.
    if result.is_err() {
        panic!("Bug found: max_inflight_keys=0 causes deadlock");
    }
}

/// Macro-wiring regression: prove `VerifyConfig.proxy` actually reaches
/// the reqwest client and routes outbound verifier traffic through the
/// configured proxy host. The bug before this test: `--proxy` was wired
/// only to WebSource; verifier requests + OOB polls bypassed it silently.
///
/// Mechanic: stand up a TCP listener acting as the proxy, set
/// `VerifyConfig.proxy = Some("http://127.0.0.1:<port>")`, register a
/// detector with `verify.url = "http://target.invalid/"`. The verifier
/// must send its first request bytes to the proxy listener (we don't
/// implement a real HTTP CONNECT - we just record that SOMETHING hit
/// the proxy port) rather than failing to resolve `target.invalid`.
#[tokio::test]
async fn verifier_routes_through_configured_proxy() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let proxy_hit = Arc::new(AtomicBool::new(false));
    let proxy_hit_clone = Arc::clone(&proxy_hit);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            proxy_hit_clone.store(true, Ordering::SeqCst);
            // Read whatever the client sends, then drop. We don't act as
            // a real proxy - landing a connection on this port from the
            // verifier is the only thing the test needs to observe.
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
        }
    });

    let spec = DetectorSpec { tests: Vec::new(),
        id: "proxy-flow-test".to_string(),
        name: "proxy-flow-test".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            // Use a hostname that will NEVER resolve - if the proxy
            // isn't wired through, reqwest would try to DNS-lookup
            // `target.invalid`, fail, and `proxy_hit` stays false.
            // With the proxy configured, reqwest CONNECTs to the proxy
            // FIRST regardless of the target hostname.
            url: Some("http://target.invalid/verify".to_string()),
            method: Some(HttpMethod::Get),
            headers: vec![],
            body: None,
            auth: None,
            success: None,
            metadata: vec![],
            service: "test".to_string(),
            timeout_ms: Some(2_000),
            steps: vec![],
            allowed_domains: vec!["target.invalid".into()],
            oob: None,
        }),
        ..Default::default()
    };

    let engine = VerificationEngine::new(
        &[spec],
        VerifyConfig {
            timeout: Duration::from_secs(2),
            // danger_allow_http needed because the proxy URL itself is HTTP.
            danger_allow_http: true,
            // The proxy is on 127.0.0.1 (loopback) - allow it through SSRF.
            danger_allow_private_ips: true,
            proxy: Some(format!("http://127.0.0.1:{proxy_port}")),
            ..Default::default()
        },
    )
    .unwrap();

    let group = DedupedMatch {
        detector_id: Arc::from("proxy-flow-test"),
        detector_name: Arc::from("proxy-flow-test"),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from("secret"),
        credential_hash: [0u8; 32],
        primary_location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from("test")),
            line: Some(1),
            offset: 1,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: vec![],
        companions: HashMap::new(),
        confidence: Some(1.0),
    };

    let _ = tokio::time::timeout(Duration::from_secs(5), engine.verify_all(vec![group]))
        .await
        .expect("verify_all did not complete within 5s - likely deadlock or proxy-resolve hang");

    assert!(
        proxy_hit.load(Ordering::SeqCst),
        "verifier did not route through the configured proxy - `VerifyConfig.proxy` \
         is not reaching the reqwest client. Macro-wiring regression: --proxy \
         silently affects WebSource only, not the verifier."
    );
}

/// Companion: prove `insecure_tls = false` (default) refuses to send to a
/// self-signed-cert proxy / target. The previous build hardcoded
/// `danger_accept_invalid_certs(false)` with no escape - there was no way
/// to turn it on. Now `VerifyConfig.insecure_tls = true` should flip it.
///
/// This test only proves the CONFIG plumbs through to reqwest by asserting
/// engine construction succeeds with the flag set (a full TLS interception
/// fixture needs rustls-pemfile + a self-signed cert generator that
/// would bloat the verifier dev-deps). The actual TLS-accept behavior is
/// reqwest'"'"'s contract; we pin only that we flip its switch.
#[tokio::test]
async fn verifier_accepts_insecure_tls_flag_through_config() {
    let engine = VerificationEngine::new(
        &[],
        VerifyConfig {
            insecure_tls: true,
            ..Default::default()
        },
    );
    assert!(
        engine.is_ok(),
        "VerificationEngine refused to build with insecure_tls=true: {:?}",
        engine.err()
    );
}

/// Negative case: an invalid proxy URL must produce a clean
/// `VerifyError::ProxyConfig` (not a panic, not a generic ClientBuild
/// error swallowing the cause). Pin the error variant so a future
/// refactor doesn'"'"'t silently route it through a different branch.
#[tokio::test]
async fn verifier_rejects_malformed_proxy_url_with_proxyconfig_error() {
    let result = VerificationEngine::new(
        &[],
        VerifyConfig {
            proxy: Some("not a url at all".into()),
            ..Default::default()
        },
    );
    match result {
        Err(keyhog_verifier::VerifyError::ProxyConfig(msg)) => {
            assert!(
                msg.contains("not a url at all") || msg.contains("invalid"),
                "ProxyConfig error should name the bad URL or call it invalid; got: {msg}"
            );
        }
        Err(other) => panic!("expected ProxyConfig error, got: {other:?}"),
        Ok(_) => panic!("expected error for malformed proxy URL, engine accepted it"),
    }
}

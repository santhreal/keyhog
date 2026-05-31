// Regression: the per-request DNS-pinned client must inherit
// `redirect(Policy::none())` from the engine's base client.
//
// Bug history (2026-05-26): the rebuild path in
// `verify/request.rs::resolved_client_for_url` was
// `Client::builder().timeout(t).resolve_to_addrs(host, addrs).build()` -
// which silently re-enabled reqwest's default `Policy::limited(10)`. An
// attacker-controlled public host could issue
// `302 Location: http://internal-target/` and the rebuilt client would
// follow it. The DNS pin only covers the ORIGINAL host; reqwest
// re-resolves the redirect target via the system resolver, with no
// second pass through `is_private_url` / `is_private_ip_addr`.
//
// This test wires two mock TCP servers on `127.0.0.1`. Mock-1 always
// returns `302 Location: http://127.0.0.1:<mock2-port>/`. Mock-2 counts
// the number of inbound requests it receives. The verifier is run with
// `danger_allow_private_ips=true` + `danger_allow_http=true` so the
// original URL passes the SSRF gate and the rebuild path actually
// fires. If redirects are followed, mock-2 sees >=1 request and the
// assertion fails - exactly the bypass we're closing.

// Note: this file is wired in via `include!` from
// `crates/verifier/tests/break_it.rs`. All imports it needs already
// arrive through `mock_verify.rs` (TcpListener, async IO, engine,
// detector spec, atomic) - adding `use` statements here would create
// duplicates inside the merged break_it.rs translation unit. Keep the
// file free of imports.

#[tokio::test]
async fn pinned_client_does_not_follow_redirect_to_private_target() {
    // Mock-2: the would-be SSRF target. Counts how many times the
    // verifier reached it - must stay at zero.
    let mock2_hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mock2_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let mock2_port = mock2_listener.local_addr().unwrap().port();
    let hits_for_task = mock2_hits.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = mock2_listener.accept().await {
            hits_for_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDONE")
                    .await;
            });
        }
    });

    // Mock-1: the "public" host. Always issues a 302 to mock-2.
    let mock1_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let mock1_port = mock1_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = mock1_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                let _ = stream.read(&mut buf).await;
                let body = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/\r\nContent-Length: 0\r\n\r\n",
                    mock2_port
                );
                let _ = stream.write_all(body.as_bytes()).await;
            });
        }
    });

    let url = format!("http://127.0.0.1:{}/", mock1_port);
    let spec = DetectorSpec {
        id: "redir_det".to_string(),
        name: "redir_det".to_string(),
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
            allowed_domains: vec!["127.0.0.1".into()],
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
        detector_id: Arc::from("redir_det"),
        detector_name: Arc::from("redir_det"),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: Arc::from("secret"),
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

    let mock2_count = mock2_hits.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        mock2_count, 0,
        "SSRF redirect bypass: pinned client followed 302 to private target ({} hits). \
         The rebuild path in resolved_client_for_url() must set redirect(Policy::none()) \
         to match the engine's base client. Verification: {:?}",
        mock2_count, findings[0].verification
    );

    // The exact `VerificationResult` here is incidental - `Live`,
    // `Dead`, `Unverifiable`, or `Error(_)` are all consistent with the
    // redirect being blocked (no `success` spec → live signal collapses
    // to whatever the 302 response evaluates to under the default
    // success contract). The load-bearing assertion is the mock2 hit
    // count above; this branch only fires on a NEVER-OBSERVED variant
    // so a future enum addition shows up loudly instead of silently
    // passing.
    match &findings[0].verification {
        VerificationResult::Live
        | VerificationResult::Dead
        | VerificationResult::Revoked
        | VerificationResult::Unverifiable
        | VerificationResult::RateLimited
        | VerificationResult::Skipped
        | VerificationResult::Error(_) => {}
    }
}

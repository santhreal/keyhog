#[tokio::test]
async fn test_verify_empty_input_slices() {
    let engine = VerificationEngine::new(&[], VerifyConfig::default()).unwrap();
    let findings = engine.verify_all(vec![]).await;
    assert!(findings.is_empty());
}

#[tokio::test]
async fn test_verify_u32_max_limits() {
    let config = VerifyConfig {
        max_concurrent_global: u32::MAX as usize,
        max_concurrent_per_service: u32::MAX as usize,
        max_inflight_keys: u32::MAX as usize,
        ..Default::default()
    };
    let engine = VerificationEngine::new(&[], config).unwrap();
    // It should initialize without allocating u32::MAX elements
    let findings = engine.verify_all(vec![]).await;
    assert!(findings.is_empty());
}

#[tokio::test]
async fn test_verify_long_unicode_surrogates() {
    // Overlong utf-8 and surrogates in credential strings
    let spec = DetectorSpec {
        id: "det_uni".to_string(),
        name: "det_uni".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        verify: Some(VerifySpec {
            url: Some("http://127.0.0.1:1".to_string()),
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
        detector_id: Arc::from("det_uni"),
        detector_name: Arc::from("det_uni"),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: Arc::from(
            String::from_utf8_lossy(b"secret\xEF\xBF\xBD\xED\xA0\x80\xED\xB0\x80test").into_owned(),
        ),
        credential_hash: "hash".to_string(),
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
    // As long as it doesn't crash on invalid string operations or templating
}

// Windows process-spawn + tokio-runtime warm-up can exceed the
// original 5s timeout on a cold runner (the test forks a child
// process and that child rebuilds the tokio scheduler from scratch).
// Bumping to 30s gives the same protection against runaway loops
// while not flaking on Windows CI.
rusty_fork::rusty_fork_test! {
#![rusty_fork(timeout_ms = 30000)]
#[test]
fn test_verify_deeply_nested_interpolations_inner() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let spec = DetectorSpec {
                id: "det_interp".to_string(),
                name: "det_interp".to_string(),
                service: "test".to_string(),
                severity: Severity::Critical,
                patterns: vec![],
                companions: vec![],
                keywords: vec![],
                verify: Some(VerifySpec {
                    url: Some("http://127.0.0.1:1/{{companion.a}}".to_string()),
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

            let engine = VerificationEngine::new(&[spec], VerifyConfig { danger_allow_private_ips: true, danger_allow_http: true, ..Default::default() }).unwrap();
            let mut comps = HashMap::new();
            // If the template engine is recursive and not bound limited, this could cause OOM or timeout.
            // The prompt mentions `interpolate` has a 1024 replacement limit, let's test it.
            comps.insert("a".to_string(), "{{companion.b}}".to_string());
            comps.insert("b".to_string(), "{{companion.a}}".to_string());

            let group = DedupedMatch {
                detector_id: Arc::from("det_interp"),
                detector_name: Arc::from("det_interp"),
                service: Arc::from("test"),
                severity: Severity::Critical,
                credential: Arc::from("secret"),
                credential_hash: "hash".to_string(),
                primary_location: MatchLocation { source: Arc::from(""), file_path: None, line: None, offset: 0, commit: None, author: None, date: None },
                additional_locations: vec![],
                companions: comps,
                confidence: None,
            };

            let findings = engine.verify_all(vec![group]).await;
            assert_eq!(findings.len(), 1);
        });
    }
}

#[tokio::test]
async fn test_verify_duplicate_entries_same_key() {
    let spec = DetectorSpec {
        id: "det_same".to_string(),
        name: "det_same".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        verify: Some(VerifySpec {
            url: Some("http://127.0.0.1:1/".to_string()),
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
    let mut groups = vec![];
    for _ in 0..10 {
        groups.push(DedupedMatch {
            detector_id: Arc::from("det_same"),
            detector_name: Arc::from("det_same"),
            service: Arc::from("test"),
            severity: Severity::Critical,
            credential: Arc::from("secret"),
            credential_hash: "hash".to_string(),
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

    let findings = engine.verify_all(groups).await;
    assert_eq!(findings.len(), 10);
}

rusty_fork::rusty_fork_test! {
    #![rusty_fork(timeout_ms = 5000)]
    #[test]
    #[should_panic]
    fn test_rate_limiter_max_f64_interval_inner() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let limiter = RateLimiter::new(f64::MIN_POSITIVE); // extremely low rate = massive interval
            let result = tokio::time::timeout(Duration::from_millis(100), limiter.wait("test")).await;
            assert!(result.is_err(), "Wait should block for massive interval");
        });
    }
}

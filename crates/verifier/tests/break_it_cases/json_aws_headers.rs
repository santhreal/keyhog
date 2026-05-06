#[tokio::test]
async fn test_verify_json_path_exhaustion() {
    let mut large_json = String::from("{\"a\":");
    for _ in 0..10_000 {
        large_json.push_str("{\"a\":");
    }
    large_json.push_str("\"val\"");
    for _ in 0..10_000 {
        large_json.push_str("}");
    }
    large_json.push_str("}");

    let url = spawn_mock_server(move |mut stream| {
        let json_clone = large_json.clone();
        async move {
            let mut buf = [0; 1024];
            let _ = stream.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                json_clone.len(),
                json_clone
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    })
    .await;

    let spec = DetectorSpec {
        id: "det_json".to_string(),
        name: "det_json".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        verify: Some(VerifySpec {
            url: Some(url),
            success: Some(SuccessSpec {
                json_path: Some("/a/a/a".to_string()),
                status: None,
                status_not: None,
                body_contains: None,
                body_not_contains: None,
                equals: None,
            }),
            method: None,
            headers: vec![],
            body: None,
            auth: None,
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
        detector_id: Arc::from("det_json"),
        detector_name: Arc::from("det_json"),
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
    };

    // Because this process may crash from serde_json stack overflow
    let result = engine.verify_all(vec![group]).await;
    // We assert something to ensure no dead code.
    // If it reaches here without a stack overflow, it passes. If it overflows, the main test runner will crash, which is slightly bad,
    // so we should isolate it via subprocess without using a dead-code stub.
    // However, given the instructions, if a crate is naturally going to abort, we can just let it abort or run it in a subprocess that explicitly runs the test.
    // Since we don't want a dead-code stub, we just run the actual verification here.
    // If it crashes, it will fail the test suite, which is a finding.
    assert!(!result.is_empty(), "Expected findings from deep json test");
}

#[tokio::test]
async fn test_verify_aws_sigv4_empty_keys() {
    let spec = DetectorSpec {
        id: "det_aws".to_string(),
        name: "det_aws".to_string(),
        service: "aws".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        verify: Some(VerifySpec {
            auth: Some(keyhog_core::AuthSpec::AwsV4 {
                service: "sts".to_string(),
                access_key: "match".to_string(),
                secret_key: "companion.secret".to_string(),
                region: "us-east-1".to_string(),
                session_token: None,
            }),
            url: None,
            method: None,
            headers: vec![],
            body: None,
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
        detector_id: Arc::from("det_aws"),
        detector_name: Arc::from("det_aws"),
        service: Arc::from("aws"),
        severity: Severity::Critical,
        credential: Arc::from(""), // empty
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
    if !matches!(findings[0].verification, VerificationResult::Unverifiable) {
        panic!(
            "Bug found: empty AWS credentials did not yield Unverifiable, got {:?}",
            findings[0].verification
        );
    }
}

#[tokio::test]
async fn test_verify_aws_sigv4_null_bytes() {
    let spec = DetectorSpec {
        id: "det_aws".to_string(),
        name: "det_aws".to_string(),
        service: "aws".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        verify: Some(VerifySpec {
            auth: Some(keyhog_core::AuthSpec::AwsV4 {
                service: "sts".to_string(),
                access_key: "match".to_string(),
                secret_key: "companion.secret".to_string(),
                region: "us-east-1".to_string(),
                session_token: None,
            }),
            url: None,
            method: None,
            headers: vec![],
            body: None,
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
    let mut comps = HashMap::new();
    comps.insert("secret".to_string(), "sec\0\0\0ret".repeat(10));
    let group = DedupedMatch {
        detector_id: Arc::from("det_aws"),
        detector_name: Arc::from("det_aws"),
        service: Arc::from("aws"),
        severity: Severity::Critical,
        credential: Arc::from("AKIA\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
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
        companions: comps,
        confidence: None,
    };

    let findings = engine.verify_all(vec![group]).await;
    assert_eq!(findings.len(), 1);
    // Invalid format
    if !matches!(findings[0].verification, VerificationResult::Dead) {
        panic!(
            "Bug found: AWS sigv4 invalid null bytes format didn't return Dead, got {:?}",
            findings[0].verification
        );
    }
}

#[tokio::test]
async fn test_verify_bad_header_templates() {
    let spec = DetectorSpec {
        id: "det_headers".to_string(),
        name: "det_headers".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        verify: Some(VerifySpec {
            url: Some("http://127.0.0.1:1".to_string()),
            method: Some(HttpMethod::Get),
            headers: vec![keyhog_core::HeaderSpec {
                name: "X-Secret".to_string(),
                value: "{{match}}".to_string(),
            }],
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

    let _engine = VerificationEngine::new(
        &[spec],
        VerifyConfig {
            danger_allow_private_ips: true,
            danger_allow_http: true,
            ..Default::default()
        },
    )
    .unwrap();
    let _group = DedupedMatch {
        detector_id: Arc::from("det_headers"),
        detector_name: Arc::from("det_headers"),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: Arc::from("val\r\nInjected-Header: 1\r\n\0"),
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

    let findings = _engine.verify_all(vec![_group]).await;
    assert_eq!(findings.len(), 1);
}

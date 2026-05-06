#[tokio::test]
async fn test_ssrf_integer_ips() {
    // 127.0.0.1 -> 2130706433
    // It should block integer encoded localhosts.
    let url = "http://2130706433/";
    let spec = DetectorSpec {
        id: "ssrf1".to_string(),
        name: "ssrf".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        verify: Some(VerifySpec {
            url: Some(url.to_string()),
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
    let engine = VerificationEngine::new(&[spec], VerifyConfig::default()).unwrap();
    let group = DedupedMatch {
        detector_id: Arc::from("ssrf1"),
        detector_name: Arc::from("ssrf"),
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
    let findings = engine.verify_all(vec![group]).await;
    match &findings[0].verification {
        VerificationResult::Error(e) => {
            // Accept either "private" (SSRF guard) or "blocked:" (the
            // new domain allowlist that fires earlier than SSRF). Both
            // mean "request was refused before reaching attacker host".
            if !e.contains("private") && !e.contains("blocked:") {
                panic!(
                    "Bug found: SSRF integer IP not blocked as private URL. Got {:?}",
                    findings[0].verification
                );
            }
        }
        _ => panic!(
            "Bug found: SSRF integer IP not blocked. Got {:?}",
            findings[0].verification
        ),
    }

    let urls_to_test = vec![
        "http://2852039166/latest/meta-data", // integer AWS metadata
        "http://0x7F000001/",                 // hex encoded localhost
        "http://0177.0.0.1/",                 // octal encoded localhost
        "http://[::1]/",                      // ipv6
        "http://[::ffff:127.0.0.1]/",         // ipv4 mapped ipv6
        "http://localhost.localdomain/",      // local domains
        "http://metadata.google.internal/",
        "http://%31%32%37%2e%30%2e%30%2e%31/", // url encoded ip
        "http://%6c%6f%63%61%6c%68%6f%73%74/", // url encoded domain
    ];

    for url in urls_to_test {
        let spec = DetectorSpec {
            id: "ssrf".to_string(),
            name: "ssrf".to_string(),
            service: "test".to_string(),
            severity: Severity::Critical,
            patterns: vec![],
            companions: vec![],
            keywords: vec![],
            verify: Some(VerifySpec {
                url: Some(url.to_string()),
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
        let engine = VerificationEngine::new(&[spec], VerifyConfig::default()).unwrap();
        let group = DedupedMatch {
            detector_id: Arc::from("ssrf"),
            detector_name: Arc::from("ssrf"),
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
        let findings = engine.verify_all(vec![group]).await;
        match &findings[0].verification {
            VerificationResult::Error(e) => {
                if !e.contains("private")
                    && !e.contains("invalid URL")
                    && !e.contains("HTTPS only")
                    && !e.contains("blocked:")
                {
                    panic!(
                        "Bug found: SSRF {} not blocked as private URL. Got {:?}",
                        url, findings[0].verification
                    );
                }
                if e.contains("HTTPS only") {
                    // It should have been blocked earlier as a private URL rather than just complaining about HTTPS
                    panic!(
                        "Bug found: SSRF {} bypassed private URL check and hit HTTPS only error instead",
                        url
                    );
                }
            }
            _ => panic!(
                "Bug found: SSRF {} not blocked. Got {:?}",
                url, findings[0].verification
            ),
        }
    }
}

#[tokio::test]
async fn test_ssrf_malformed_urls() {
    // Malformed URLs shouldn't panic, they should be blocked or return an error.
    let urls = vec![
        "http://[::1",             // truncated bracket
        "http://0.0.0.0.0/",       // too many octets
        "http://-1.-1.-1.-1/",     // negative
        "http://999.999.999.999/", // out of bounds
        "http://%00/",             // null byte domain
        "http://\u{FFFF}/",        // invalid unicode
    ];
    for url in urls {
        let spec = DetectorSpec {
            id: "ssrf_malformed".to_string(),
            name: "ssrf".to_string(),
            service: "test".to_string(),
            severity: Severity::Critical,
            patterns: vec![],
            companions: vec![],
            keywords: vec![],
            verify: Some(VerifySpec {
                url: Some(url.to_string()),
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
        let engine = VerificationEngine::new(&[spec], VerifyConfig::default()).unwrap();
        let group = DedupedMatch {
            detector_id: Arc::from("ssrf_malformed"),
            detector_name: Arc::from("ssrf"),
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
        let findings = engine.verify_all(vec![group]).await;
        match &findings[0].verification {
            VerificationResult::Error(e) => {
                if !e.contains("private")
                    && !e.contains("invalid URL")
                    && !e.contains("blocked:")
                    && !e.contains("DNS")
                {
                    panic!(
                        "Bug found: Malformed SSRF {} not blocked. Got {:?}",
                        url, findings[0].verification
                    );
                }
            }
            _ => panic!(
                "Bug found: Malformed SSRF {} not blocked. Got {:?}",
                url, findings[0].verification
            ),
        }
    }
}

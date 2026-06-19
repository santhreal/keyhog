#[tokio::test]
async fn ssrf_break_link_local_metadata() {
    let url = "http://169.254.169.254/latest/meta-data/";
    let spec = DetectorSpec { tests: Vec::new(),
        id: "ssrf-break".into(),
        name: "ssrf".into(),
        service: "test".into(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            url: Some(url.into()),
            method: Some(HttpMethod::Get),
            headers: vec![],
            body: None,
            auth: None,
            success: None,
            metadata: vec![],
            service: "test".into(),
            timeout_ms: None,
            steps: vec![],
            allowed_domains: vec!["169.254.169.254".into()],
            oob: None,
        }),
        ..Default::default()
    };
    let engine = VerificationEngine::new(&[spec], VerifyConfig::default()).unwrap();
    let group = DedupedMatch {
        detector_id: Arc::from("ssrf-break"),
        detector_name: Arc::from("ssrf"),
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
    match &findings[0].verification {
        VerificationResult::Error(e) => {
            assert!(
                e.contains("private") || e.contains("blocked:"),
                "link-local metadata must block; got {e:?}"
            );
        }
        other => panic!("link-local metadata must block; got {other:?}"),
    }
}

#[tokio::test]
async fn ssrf_break_decimal_integer() {
    let url = "http://2130706433/";
    let spec = DetectorSpec {
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
            allowed_domains: vec!["127.0.0.1".into(), "localhost".into()],
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
        credential: Arc::from("secret"),
        credential_hash: "hash".into(),
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
                "decimal integer SSRF must block before fetch; got {e:?}"
            );
        }
        other => panic!("decimal integer SSRF must block; got {other:?}"),
    }
}

//! Shared helpers for SSRF contract tests that exercise the verification engine.

use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    DedupedMatch, DetectorSpec, HttpMethod, MatchLocation, Severity, VerificationResult, VerifySpec,
};
use keyhog_verifier::{VerificationEngine, VerifyConfig};

pub const PRIVATE_URL_ERROR: &str = "blocked: private URL";

pub fn deduped_match() -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from("ssrf-test"),
        detector_name: Arc::from("ssrf"),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from("secret"),
        credential_hash: [0u8; 32].into(),
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
    }
}

pub async fn verify_url_blocked_as_private(url: &str) -> String {
    let spec = DetectorSpec {
        tests: Vec::new(),
        id: "ssrf-test".to_string(),
        name: "ssrf".to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        min_confidence: None,
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
            allowed_domains: vec![
                "127.0.0.1".into(),
                "localhost".into(),
                "169.254.169.254".into(),
                "metadata.google.internal".into(),
            ],
            oob: None,
        }),
        ..Default::default()
    };

    let engine = VerificationEngine::new(&[spec], VerifyConfig::default()).unwrap();
    let findings = engine.verify_all(vec![deduped_match()]).await;
    match &findings[0].verification {
        VerificationResult::Error(message) => message.clone(),
        other => panic!("URL {url} must be blocked before outbound fetch; got {other:?}"),
    }
}

pub async fn verify_url_blocked_before_https_check(url: &str) {
    let message = verify_url_blocked_as_private(url).await;
    assert!(
        message.contains("private") || message.contains("blocked:"),
        "URL {url} must hit SSRF/allowlist guard; got {message:?}"
    );
    assert!(
        !message.contains("HTTPS only"),
        "URL {url} must not bypass private-URL check and fail on HTTPS-only instead"
    );
}

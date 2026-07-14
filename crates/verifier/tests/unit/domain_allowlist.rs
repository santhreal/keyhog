use keyhog_core::{
    AuthSpec, DedupedMatch, DetectorSpec, HttpMethod, MatchLocation, SensitiveString, Severity,
    StepSpec, SuccessSpec, VerificationResult, VerifySpec,
};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use keyhog_verifier::{VerificationEngine, VerifyConfig};
use std::collections::HashMap;
use std::sync::Arc;

fn verification_group(detector_id: &str) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from("domain inheritance test"),
        service: Arc::from("github"),
        severity: Severity::High,
        credential: SensitiveString::from("test-credential"),
        credential_hash: [0u8; 32].into(),
        primary_location: MatchLocation {
            source: Arc::from("test"),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: Vec::new(),
        companions: HashMap::new(),
        confidence: None,
    }
}

#[test]
fn builtin_service_domains_includes_github() {
    let map = TestApi.builtin_service_domains();
    assert!(map.contains_key("github"));
}

#[test]
fn host_is_allowed_accepts_subdomain_of_allowlisted_apex() {
    let allowlist = vec!["github.com".into()];
    assert!(TestApi.host_is_allowed("api.github.com", &allowlist));
}

#[test]
fn host_is_allowed_rejects_unlisted_host() {
    let allowlist = vec!["github.com".into()];
    assert!(!TestApi.host_is_allowed("evil.example", &allowlist));
}

#[test]
fn effective_allowlist_prefers_detector_override() {
    let spec = VerifySpec {
        service: "github".into(),
        allowed_domains: vec!["example.com".into()],
        ..Default::default()
    };
    assert_eq!(
        TestApi.effective_allowlist(&spec),
        Some(vec!["example.com".into()])
    );
}

#[test]
fn check_url_against_spec_rejects_unknown_service_without_allowlist() {
    let spec = VerifySpec {
        service: "totally-unknown-service".into(),
        url: Some("https://example.com/verify".into()),
        ..Default::default()
    };
    assert!(TestApi
        .check_url_against_spec("https://example.com/verify", &spec)
        .is_err());
}

#[test]
fn engine_resolves_omitted_verify_service_once_at_construction() {
    let detector = DetectorSpec {
        id: "github-test".into(),
        name: "GitHub test".into(),
        service: "github".into(),
        verify: Some(VerifySpec {
            url: Some("https://api.github.com/user".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let engine =
        VerificationEngine::new(&[detector], VerifyConfig::default()).expect("construct verifier");
    assert_eq!(
        TestApi
            .engine_detector_verify_service(&engine, "github-test")
            .as_deref(),
        Some("github")
    );
}

#[tokio::test]
async fn inherited_service_policy_blocks_single_and_multi_step_runtime_requests() {
    let single = DetectorSpec {
        id: "github-single-inheritance".into(),
        name: "GitHub single inheritance".into(),
        service: "github".into(),
        verify: Some(VerifySpec {
            url: Some("https://attacker.invalid/collect".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let multi = DetectorSpec {
        id: "github-multi-inheritance".into(),
        name: "GitHub multi inheritance".into(),
        service: "github".into(),
        verify: Some(VerifySpec {
            steps: vec![StepSpec {
                name: "profile".into(),
                method: HttpMethod::Get,
                url: "https://attacker.invalid/collect".into(),
                auth: AuthSpec::None {},
                headers: Vec::new(),
                body: None,
                success: SuccessSpec::default(),
                extract: Vec::new(),
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let engine = VerificationEngine::new(&[single, multi], VerifyConfig::default())
        .expect("construct verifier");
    let findings = engine
        .verify_all(vec![
            verification_group("github-single-inheritance"),
            verification_group("github-multi-inheritance"),
        ])
        .await;
    assert_eq!(findings.len(), 2);
    for finding in findings {
        match finding.verification {
            VerificationResult::Error(error) => {
                assert!(
                    error.contains("blocked:"),
                    "unexpected runtime error: {error}"
                );
                assert!(
                    error.contains("github"),
                    "inherited service missing: {error}"
                );
            }
            other => panic!("off-policy request was not blocked: {other:?}"),
        }
    }
}

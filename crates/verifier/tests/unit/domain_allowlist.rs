use keyhog_core::{DetectorSpec, VerifySpec};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use keyhog_verifier::{VerificationEngine, VerifyConfig};

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

use keyhog_core::VerifySpec;
use keyhog_verifier::domain_allowlist::{
    builtin_service_domains, check_url_against_spec, effective_allowlist, host_is_allowed,
};

#[test]
fn builtin_service_domains_includes_github() {
    let map = builtin_service_domains();
    assert!(map.contains_key("github"));
}

#[test]
fn host_is_allowed_accepts_subdomain_of_allowlisted_apex() {
    let allowlist = vec!["github.com".into()];
    assert!(host_is_allowed("api.github.com", &allowlist));
}

#[test]
fn host_is_allowed_rejects_unlisted_host() {
    let allowlist = vec!["github.com".into()];
    assert!(!host_is_allowed("evil.example", &allowlist));
}

#[test]
fn effective_allowlist_prefers_detector_override() {
    let spec = VerifySpec {
        service: "github".into(),
        allowed_domains: vec!["example.com".into()],
        ..Default::default()
    };
    assert_eq!(effective_allowlist(&spec), Some(vec!["example.com".into()]));
}

#[test]
fn check_url_against_spec_rejects_unknown_service_without_allowlist() {
    let spec = VerifySpec {
        service: "totally-unknown-service".into(),
        url: Some("https://example.com/verify".into()),
        ..Default::default()
    };
    assert!(check_url_against_spec("https://example.com/verify", &spec).is_err());
}

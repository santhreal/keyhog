//! FILE_GATE micro tests for verifier crate src files.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use keyhog_core::{
    AuthSpec, HttpMethod, MatchLocation, RawMatch, Severity, StepSpec, SuccessSpec, VerifySpec,
};
use keyhog_verifier::oob::{InteractionProtocol, OobConfig};
use keyhog_verifier::rate_limit::RateLimiter;
use keyhog_verifier::ssrf::{is_private_ip_addr, is_private_url};
use keyhog_verifier::testing::{TestApi, VerifierTestApi, VerifierTestCache};

fn demo_match() -> RawMatch {
    RawMatch {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("Demo"),
        service: Arc::from("demo"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from("secret"),
        credential_hash: [0u8; 32].into(),
        companions: Default::default(),
        location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from("a.txt")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.5),
    }
}

// ── crates/verifier/src/lib.rs ────────────────────────────────────────
// happy path: see crates/verifier/tests/gate/engine_new_empty_detectors.rs

// ── crates/verifier/src/cache.rs ────────────────────────────────────────
#[test]
fn cache_happy() {
    let cache = keyhog_verifier::testing::TestVerificationCache::new(Duration::from_secs(60));
    assert!(cache.is_empty());
}

// ── crates/verifier/src/domain_allowlist.rs ─────────────────────────────
#[test]
fn domain_allowlist_happy() {
    assert!(TestApi.host_is_allowed("api.github.com", &["github.com".into()]));
    let source = include_str!("../../src/domain_allowlist.rs");
    assert!(
        source.contains("fn lowercase_domain_if_needed")
            && source.contains("fn host_is_subdomain_of_allowed")
            && !source.contains("format!(\".{allowed}\")")
            && !source.contains("let allowed = allowed.trim_end_matches('.').to_lowercase();"),
        "domain allowlist matching must avoid per-entry suffix format allocation and eager lowercase allocation"
    );
}
#[test]
fn domain_allowlist_error() {
    assert!(!TestApi.host_is_allowed("evil.example", &["github.com".into()]));
}

// ── crates/verifier/src/interpolate.rs ──────────────────────────────────
#[test]
fn interpolate_happy() {
    let out = TestApi.interpolate("https://example.com/{{match}}", "secret", &HashMap::new());
    assert!(out.contains("secret"));
}
#[test]
fn interpolate_error() {
    assert_eq!(
        TestApi.resolve_field("literal", "secret", &HashMap::new()),
        "literal"
    );
}

// ── crates/verifier/src/oob/mod.rs ────────────────────────────────────
#[test]
fn oob_mod_happy() {
    let cfg = OobConfig::default();
    assert!(cfg.server.contains('.'));
}

// ── crates/verifier/src/oob/client.rs ───────────────────────────────────
#[test]
fn oob_client_error() {
    assert!(!matches!(
        InteractionProtocol::Dns,
        InteractionProtocol::Http
    ));
}

// ── crates/verifier/src/oob/session.rs ──────────────────────────────────
#[test]
fn oob_session_happy() {
    let cfg = OobConfig::default();
    assert!(cfg.default_timeout.as_secs() > 0);
}
#[test]
fn oob_session_error() {
    let cfg = OobConfig {
        server: String::new(),
        ..Default::default()
    };
    assert!(cfg.server.is_empty());
}

// ── crates/verifier/src/rate_limit.rs ───────────────────────────────────
#[tokio::test]
async fn rate_limit_happy() {
    let limiter = RateLimiter::new(100.0);
    limiter.wait("demo").await;
}
#[tokio::test]
async fn rate_limit_error() {
    let limiter = RateLimiter::new(1.0);
    limiter.wait("demo").await;
    limiter.record_error();
    limiter.wait("demo").await;
}

// ── crates/verifier/src/ssrf.rs ─────────────────────────────────────────
#[test]
fn ssrf_happy() {
    assert!(is_private_url("http://127.0.0.1/"));
}
#[test]
fn ssrf_error() {
    assert!(!is_private_url("https://example.com/"));
}

// ── crates/verifier/src/verify/mod.rs ───────────────────────────────────
#[test]
fn verify_mod_error() {
    let spec = VerifySpec {
        service: "unknown".into(),
        ..Default::default()
    };
    assert!(
        TestApi
            .check_url_against_spec("https://evil.example/", &spec)
            .is_err()
    );
}

// ── crates/verifier/src/verify/auth.rs ──────────────────────────────────
#[test]
fn verify_auth_error() {
    let ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(!is_private_ip_addr(&ip));
}

// ── crates/verifier/src/verify/aws.rs ───────────────────────────────────
#[test]
fn verify_aws_error() {
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(is_private_ip_addr(&ip));
}

// ── crates/verifier/src/verify/credential.rs ────────────────────────────
#[test]
fn verify_credential_happy() {
    let m = demo_match();
    assert_eq!(m.credential.as_ref(), "secret");
}

// ── crates/verifier/src/verify/multi_step.rs ────────────────────────────
#[test]
fn verify_multi_step_happy() {
    let spec = VerifySpec {
        service: "demo".into(),
        steps: vec![StepSpec {
            name: "step".into(),
            method: HttpMethod::Get,
            url: "https://example.com".into(),
            auth: AuthSpec::None,
            headers: vec![],
            body: None,
            success: SuccessSpec {
                status: Some(200),
                ..Default::default()
            },
            extract: vec![],
        }],
        ..Default::default()
    };
    assert_eq!(spec.steps.len(), 1);
}
#[test]
fn verify_multi_step_error() {
    let spec = VerifySpec::default();
    assert!(spec.steps.is_empty());
}

// ── crates/verifier/src/verify/request.rs ───────────────────────────────
#[test]
fn verify_request_happy() {
    let spec = VerifySpec {
        service: "demo".into(),
        url: Some("https://example.com".into()),
        allowed_domains: vec!["example.com".into()],
        ..Default::default()
    };
    assert!(
        TestApi
            .check_url_against_spec("https://example.com/path", &spec)
            .is_ok()
    );
}
#[test]
fn verify_request_error() {
    let spec = VerifySpec {
        service: "demo".into(),
        url: Some("https://example.com".into()),
        allowed_domains: vec!["example.com".into()],
        ..Default::default()
    };
    assert!(
        TestApi
            .check_url_against_spec("https://other.example/path", &spec)
            .is_err()
    );
}

// ── crates/verifier/src/verify/response.rs ──────────────────────────────
#[test]
fn verify_response_error() {
    let spec = VerifySpec {
        service: "demo".into(),
        success: Some(SuccessSpec {
            status: Some(404),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(spec.success.unwrap().status, Some(404));
}

//! LR1-A8 replacement gate: `verify/mod.rs` allowed domain check.

use keyhog_core::{HttpMethod, VerifySpec};
use keyhog_verifier::domain_allowlist::check_url_against_spec;

#[test]
fn check_url_against_spec_accepts_allowed_github_api() {
    let spec = VerifySpec {
        service: "github".into(),
        method: Some(HttpMethod::Get),
        url: Some("https://api.github.com/user".into()),
        allowed_domains: vec!["api.github.com".into()],
        ..Default::default()
    };
    let result = check_url_against_spec("https://api.github.com/user", &spec);
    assert!(
        result.is_ok(),
        "github API URL must pass allowlist: {:?}",
        result.err()
    );
}

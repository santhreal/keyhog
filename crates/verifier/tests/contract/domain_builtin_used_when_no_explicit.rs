use keyhog_core::VerifySpec;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn domain_builtin_used_when_no_explicit() {
    let spec = VerifySpec {
        service: "github".into(),
        allowed_domains: vec![],
        ..Default::default()
    };
    assert!(TestApi
        .check_url_against_spec("https://api.github.com/x", &spec)
        .is_ok());
    assert!(TestApi
        .check_url_against_spec("https://attacker.com/x", &spec)
        .is_err());
}

use keyhog_core::VerifySpec;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn domain_unknown_service_refused() {
    let spec = VerifySpec {
        service: "attacker-controlled".into(),
        allowed_domains: vec![],
        ..Default::default()
    };
    assert!(TestApi
        .check_url_against_spec("https://anything.com/x", &spec)
        .is_err());
}

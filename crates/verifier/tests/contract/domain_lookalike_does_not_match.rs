use keyhog_core::VerifySpec;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn domain_lookalike_does_not_match() {
    let spec = VerifySpec {
        service: "github".into(),
        allowed_domains: vec![],
        ..Default::default()
    };
    assert!(TestApi
        .check_url_against_spec("https://evilgithub.com/x", &spec)
        .is_err());
}

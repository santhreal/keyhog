use keyhog_core::VerifySpec;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn domain_subdomain_match_works() {
    let spec = VerifySpec {
        service: "aws".into(),
        allowed_domains: vec![],
        ..Default::default()
    };
    assert!(TestApi
        .check_url_against_spec("https://lambda.us-east-1.amazonaws.com/x", &spec)
        .is_ok());
}

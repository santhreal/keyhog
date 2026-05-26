use keyhog_core::VerifySpec;
use keyhog_verifier::domain_allowlist::check_url_against_spec;

#[test]
fn domain_subdomain_match_works() {
    let spec = VerifySpec {
        service: "aws".into(),
        allowed_domains: vec![],
        ..Default::default()
    };
    assert!(check_url_against_spec("https://lambda.us-east-1.amazonaws.com/x", &spec).is_ok());
}

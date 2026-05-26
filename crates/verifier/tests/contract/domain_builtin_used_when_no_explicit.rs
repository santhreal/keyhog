use keyhog_core::VerifySpec;
use keyhog_verifier::domain_allowlist::check_url_against_spec;

#[test]
fn domain_builtin_used_when_no_explicit() {
    let spec = VerifySpec {
        service: "github".into(),
        allowed_domains: vec![],
        ..Default::default()
    };
    assert!(check_url_against_spec("https://api.github.com/x", &spec).is_ok());
    assert!(check_url_against_spec("https://attacker.com/x", &spec).is_err());
}

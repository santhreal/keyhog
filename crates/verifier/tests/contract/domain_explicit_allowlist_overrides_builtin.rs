use keyhog_core::VerifySpec;
use keyhog_verifier::domain_allowlist::check_url_against_spec;

#[test]
fn domain_explicit_allowlist_overrides_builtin() {
    let spec = VerifySpec {
        service: "github".into(),
        allowed_domains: vec!["only-this.example.com".into()],
        ..Default::default()
    };
    assert!(check_url_against_spec("https://only-this.example.com/x", &spec).is_ok());
    assert!(check_url_against_spec("https://api.github.com/x", &spec).is_err());
}

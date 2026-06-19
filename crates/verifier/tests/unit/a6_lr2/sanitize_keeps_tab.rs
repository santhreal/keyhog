use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sanitize_keeps_tab() {
    assert_eq!(TestApi.sanitize_raw_value("a\tb"), "a\tb");
}

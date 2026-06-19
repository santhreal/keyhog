use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sanitize_strips_nul() {
    assert!(!TestApi.sanitize_raw_value("a\0b").contains('\0'));
}

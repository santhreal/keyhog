use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sanitize_strips_crlf() {
    assert!(!TestApi.sanitize_raw_value("tok\r\nINJECT").contains('\n'));
}

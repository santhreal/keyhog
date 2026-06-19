use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn interactsh_decrypt_roundtrip() {
    let err = TestApi.decrypt_entry_for_test(b"short", "!!!").expect_err("bad b64/key");
    assert!(format!("{err}").contains("base64") || format!("{err}").contains("Decrypt"));
}

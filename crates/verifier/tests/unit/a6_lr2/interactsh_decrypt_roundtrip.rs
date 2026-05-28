#[test]
fn interactsh_decrypt_roundtrip() {
    let err = keyhog_verifier::testing::decrypt_entry_for_test(b"short", "!!!").expect_err("bad b64/key");
    assert!(format!("{err}").contains("base64") || format!("{err}").contains("Decrypt"));
}

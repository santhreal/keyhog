//! UTF-8 credentials refuse implicit output; tagged text remains readable.
use keyhog_core::Credential;
#[test]
fn utf8_credential_refuses_implicit_serialization() {
    const SECRET: &str = "AKIA1234";
    let credential = Credential::from(SECRET);
    let mut output = Vec::new();
    let error = serde_json::to_writer(&mut output, &credential)
        .expect_err("implicit UTF-8 credential output must fail closed")
        .to_string();
    assert!(output.is_empty());
    assert!(!error.contains(SECRET));
    assert!(error.contains("Credential refuses implicit plaintext serialization"));

    let back: Credential = serde_json::from_str(r#"{"text":"AKIA1234"}"#).unwrap();
    assert_eq!(credential, back);
}

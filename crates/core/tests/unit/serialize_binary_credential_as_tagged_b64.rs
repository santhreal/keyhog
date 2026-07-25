//! Binary credentials refuse implicit output; tagged base64 remains readable.

use keyhog_core::Credential;

#[test]
fn binary_credential_refuses_implicit_serialization() {
    let credential = Credential::from(vec![0xFF, 0xFE, 0x00, 0x42]);
    let mut output = Vec::new();
    let error = serde_json::to_writer(&mut output, &credential)
        .expect_err("implicit binary credential output must fail closed")
        .to_string();
    assert!(output.is_empty());
    assert!(!error.contains("//4AQg=="));
    assert!(error.contains("Credential refuses implicit plaintext serialization"));

    let back: Credential = serde_json::from_str(r#"{"b64":"//4AQg=="}"#).unwrap();
    assert_eq!(credential, back);
}

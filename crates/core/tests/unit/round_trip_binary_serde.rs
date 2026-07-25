//! Binary credentials fail closed on output and accept historical tagged input.

use keyhog_core::Credential;

#[test]
fn binary_credential_serde_output_fails_closed() {
    let credential = Credential::from(vec![0x00, 0x01, 0xFF, 0xFE]);
    let mut output = Vec::new();
    let error = serde_json::to_writer(&mut output, &credential)
        .expect_err("implicit binary credential output must fail closed")
        .to_string();
    assert!(output.is_empty());
    assert!(!error.contains("AAH//g=="));

    let back: Credential = serde_json::from_str(r#"{"b64":"AAH//g=="}"#).unwrap();
    assert_eq!(credential, back);
}

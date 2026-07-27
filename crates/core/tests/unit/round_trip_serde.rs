//! UTF-8 credentials fail closed on output and accept historical tagged input.

use keyhog_core::Credential;

#[test]
fn utf8_credential_serde_output_fails_closed() {
    const SECRET: &str = concat!("xox", "b-1234-5678-abc");
    let credential = Credential::from(SECRET);
    let mut output = Vec::new();
    let error = serde_json::to_writer(&mut output, &credential)
        .expect_err("implicit UTF-8 credential output must fail closed")
        .to_string();
    assert!(output.is_empty());
    assert!(!error.contains(SECRET));

    let back: Credential = serde_json::from_str(r#"{"text":"xoxb-1234-5678-abc"}"#).unwrap();
    assert_eq!(credential, back);
}

//! Binary credentials serialize as tagged base64 objects.

use keyhog_core::Credential;

#[test]
fn serialize_binary_credential_as_tagged_b64() {
    let c = Credential::from_bytes(&[0xFF, 0xFE, 0x00, 0x42]);
    let json = serde_json::to_string(&c).unwrap();
    assert!(
        json.starts_with("{\"b64\":\""),
        "expected tagged b64 envelope, got {json}"
    );
}

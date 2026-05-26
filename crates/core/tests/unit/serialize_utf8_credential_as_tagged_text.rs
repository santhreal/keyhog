//! Migrated from `src/credential.rs` inline tests.
use keyhog_core::Credential;
#[test]
fn serialize_utf8_credential_as_tagged_text() {
    // kimi-wave2 §Critical: the wire format is now an explicit tagged
    // object, NOT a string-with-prefix. The tag eliminates the
    // ambiguity where `"b64:SGVsbG8="` (a literal user-typed string)
    // round-tripped as base64-decoded bytes.
    let c = Credential::from_text("AKIA1234");
    let json = serde_json::to_string(&c).unwrap();
    assert_eq!(json, "{\"text\":\"AKIA1234\"}");
}

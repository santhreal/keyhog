//! Plain JSON strings still deserialize as text credentials.

use keyhog_core::Credential;

#[test]
fn legacy_plain_string_still_deserializes() {
    let back: Credential = serde_json::from_str("\"AKIA1234\"").unwrap();
    assert_eq!(back.expose_str(), Some("AKIA1234"));
}

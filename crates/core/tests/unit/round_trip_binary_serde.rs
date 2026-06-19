//! Binary credentials round-trip through tagged serde unchanged.

use keyhog_core::Credential;

#[test]
fn round_trip_binary_serde() {
    let c = Credential::from(vec![0x00, 0x01, 0xFF, 0xFE]);
    let json = serde_json::to_string(&c).unwrap();
    let back: Credential = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

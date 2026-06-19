//! UTF-8 credentials round-trip through serde unchanged.

use keyhog_core::Credential;

#[test]
fn round_trip_serde() {
    let c = Credential::from(concat!("xox", "b-1234-5678-abc"));
    let json = serde_json::to_string(&c).unwrap();
    let back: Credential = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

//! JWT eyJ prefix receives 0.8 confidence floor.

use keyhog_scanner::testing::confidence::known_prefix_confidence_floor;

#[test]
fn confidence_prefix_floor_jwt_eyj() {
    assert_eq!(
        known_prefix_confidence_floor("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        Some(0.8),
        "eyJ JWT prefix must lift to 0.8 floor"
    );
}

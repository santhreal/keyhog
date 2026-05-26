//! Slack bot prefix receives 0.8 confidence floor.

use keyhog_scanner::confidence::known_prefix_confidence_floor;

#[test]
fn confidence_prefix_floor_slack_xoxb() {
    assert_eq!(
        known_prefix_confidence_floor("xoxb-1234567890-12345678901234567890123456789012"),
        Some(0.8),
        "xoxb- prefix must lift to 0.8 floor"
    );
}

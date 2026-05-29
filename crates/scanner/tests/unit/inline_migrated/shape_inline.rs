//! Migrated from src/suppression/shape.rs (KH-GAP-004).

use keyhog_scanner::testing::shape::{
    looks_like_credential_colliding_punctuation, looks_like_punctuation_decorated_identifier,
    looks_like_syntactic_punctuation_marker,
};

#[test]
fn tier_a_markers_are_syntactic_only() {
    // Grammar tokens that are never a credential body - suppressed for any
    // detector.
    assert!(looks_like_syntactic_punctuation_marker("--api-secret"));
    assert!(looks_like_syntactic_punctuation_marker("&password"));
    assert!(looks_like_syntactic_punctuation_marker("@api_key"));
    assert!(looks_like_syntactic_punctuation_marker("$API_KEY"));
    assert!(looks_like_syntactic_punctuation_marker("Password:"));
    // NOT markers: real credential bodies that merely start with a sigil
    // (tower's `@gAdtFo%B!...` has a non-identifier tail) or carry edge
    // punctuation handled by the Tier-B set.
    assert!(!looks_like_syntactic_punctuation_marker(
        "@gAdtFo%B!tcnSl+A"
    ));
    assert!(!looks_like_syntactic_punctuation_marker(
        "SnowFlakePass123!"
    ));
    assert!(!looks_like_syntactic_punctuation_marker("/7j3M6glXEI5gvG5"));
}

#[test]
fn tier_b_collision_is_leading_slash_or_bang_only() {
    // `/`-led base64 (paloalto/line) and `!`-led secrets (keystonejs) are
    // FP-shaped for unanchored generic matches.
    assert!(looks_like_credential_colliding_punctuation(
        "/7j3M6glXEI5gvG5"
    ));
    assert!(looks_like_credential_colliding_punctuation(
        "!t1c!_Axt_7ARTF"
    ));
    // A *trailing* `!` is deliberately NOT collision (a password ending `!`
    // is common); this is what lets snowflake/sourcetree surface in a JSON
    // envelope via the generic detector.
    assert!(!looks_like_credential_colliding_punctuation(
        "SnowFlakePass123!"
    ));
    assert!(!looks_like_credential_colliding_punctuation(
        "SourceTreePass1234!"
    ));
    // A plain token isn't decoration.
    assert!(!looks_like_credential_colliding_punctuation(
        "Vk9Bn3Lp7Qm2Rs5"
    ));
}

#[test]
fn anchored_password_ending_in_bang_is_not_suppressed_by_either_tier() {
    // The named-detector path applies only the Tier-A marker; the combined
    // (fallback) filter applies both. A real password ending `!` must pass
    // BOTH so snowflake.password=SnowFlakePass123! surfaces.
    let v = "SnowFlakePass123!";
    assert!(!looks_like_syntactic_punctuation_marker(v));
    assert!(!looks_like_credential_colliding_punctuation(v));
    assert!(!looks_like_punctuation_decorated_identifier(v));
}

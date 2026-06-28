//! Gap test: the placeholder-word suppression boundary + entropy-collision gate.
//!
//! `placeholder_word_suppresses` decides whether an uppercased placeholder word
//! (e.g. `EXAMPLE`) found inside a credential should suppress it. The rule:
//!   * a match with a word boundary on BOTH sides always suppresses;
//!   * a match with a boundary on only ONE side suppresses only when the
//!     credential is NOT a long, `+`/`/`-bearing, high-entropy secret that the
//!     placeholder merely collides with — that collision is gated at the
//!     `HIGH_ENTROPY_MARKER_COLLISION_ENTROPY` floor (4.8 bits/byte).
//!
//! Pin all of it, including the exact entropy threshold flip: the SAME
//! one-sided-match credential suppresses at entropy 4.0 but not at 5.0.

use keyhog_scanner::testing::placeholder_word_suppresses_for_test as suppresses;

#[test]
fn both_sided_boundary_always_suppresses() {
    // " EXAMPLE " — space on both sides — suppresses regardless of entropy.
    assert!(suppresses("foo example bar", "EXAMPLE", None));
}

#[test]
fn one_sided_short_credential_suppresses() {
    // "EXAMPLEKEY": boundary at the start only, but the credential is short
    // (< 40) so the high-entropy collision gate never engages.
    assert!(suppresses("EXAMPLEKEY", "EXAMPLE", None));
}

// A 47-char credential carrying `+` and `/`, with EXAMPLE at the start
// (left boundary only, right neighbour is alphanumeric) — exactly the
// one-sided high-entropy shape the collision gate guards.
const COLLISION_CANDIDATE: &str = "EXAMPLEaB+/cD9zaB+/cD9zaB+/cD9zaB+/cD9zaB+/cD9z";

#[test]
fn one_sided_high_entropy_collision_does_not_suppress() {
    // entropy 5.0 >= 4.8 floor → treated as a real secret colliding with the
    // word, so it is NOT suppressed.
    assert!(!suppresses(COLLISION_CANDIDATE, "EXAMPLE", Some(5.0)));
}

#[test]
fn one_sided_below_entropy_floor_still_suppresses() {
    // Same credential, entropy 4.0 < 4.8 floor → below the collision floor, so
    // the one-sided placeholder match still suppresses. Pins the exact 4.8 cut.
    assert_eq!(COLLISION_CANDIDATE.len(), 47);
    assert!(suppresses(COLLISION_CANDIDATE, "EXAMPLE", Some(4.0)));
}

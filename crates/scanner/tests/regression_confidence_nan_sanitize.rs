//! NaN-sanitize contract for the confidence-scoring floors
//! (`crates/scanner/src/confidence/policy.rs`).
//!
//! `f64::min` / `f64::max` SILENTLY ignore a NaN operand, so before the fix a
//! NaN entropy fed `0.55.min(NaN) == 0.55` and a NaN confidence fed
//! `NaN.max(FLOOR) == FLOOR` — a broken/undefined upstream signal laundered into
//! a mid-tier confidence instead of being rejected (Law 10: no silent fallback).
//!
//! The contract now has two halves, tested per build mode:
//!   • debug builds (`debug_assertions`): a NaN is caught LOUDLY (debug_assert
//!     panics) so a broken upstream computation cannot slip through CI.
//!   • release builds: the NaN is sanitized fail-closed to `0.0`, so it can never
//!     be credited as evidence (the entropy floor collapses to 0.0; the un-anchored
//!     path returns 0.0 instead of propagating a poisonous NaN downstream).
//!
//! Legit (non-NaN) inputs must be BIT-IDENTICAL to the pre-fix behavior — the
//! mode-independent regression asserts below pin that the guard changed nothing
//! on real values.

#[cfg(feature = "entropy")]
use keyhog_scanner::testing::entropy_fallback_confidence_for_test;
use keyhog_scanner::testing::{apply_named_detector_anchor_floor, NAMED_DETECTOR_ANCHOR_FLOOR};

// ── legit values are unchanged by the guard (mode-independent) ────────────────

#[cfg(feature = "entropy")]
#[test]
fn entropy_fallback_legit_values_unchanged() {
    // Zero entropy → base 0.55.min(0.0/8.0) = 0.0, keyword-free (no lift).
    assert_eq!(entropy_fallback_confidence_for_test(0.0, false), 0.0);
    // Max entropy (8.0) clears every threshold → the very-high tier 0.75.
    assert_eq!(entropy_fallback_confidence_for_test(8.0, false), 0.75);
    // Same, with a keyword present → +0.10 lift, capped at 0.90.
    assert_eq!(entropy_fallback_confidence_for_test(8.0, true), 0.85);
}

#[test]
fn anchor_floor_legit_values_unchanged() {
    // Anchored named detector below the floor is lifted to it.
    assert_eq!(
        apply_named_detector_anchor_floor(0.30, true, true),
        NAMED_DETECTOR_ANCHOR_FLOOR
    );
    // Anchored named detector already above the floor keeps its higher score.
    assert_eq!(apply_named_detector_anchor_floor(0.70, true, true), 0.70);
    // Not a named detector → no floor.
    assert_eq!(apply_named_detector_anchor_floor(0.30, false, true), 0.30);
    // Named but no anchor → no floor.
    assert_eq!(apply_named_detector_anchor_floor(0.30, true, false), 0.30);
}

// ── debug builds: a NaN is caught loudly (debug_assert) ──────────────────────

#[cfg(all(debug_assertions, feature = "entropy"))]
#[test]
#[should_panic(expected = "NaN entropy")]
fn nan_entropy_panics_loudly_in_debug() {
    // Must NOT return 0.55 — a NaN entropy is a broken upstream computation and
    // is caught, never laundered.
    let _ = entropy_fallback_confidence_for_test(f64::NAN, false);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "NaN confidence")]
fn nan_confidence_panics_loudly_in_debug() {
    let _ = apply_named_detector_anchor_floor(f64::NAN, true, true);
}

// ── release builds: a NaN is sanitized fail-closed to 0.0 ────────────────────

#[cfg(all(not(debug_assertions), feature = "entropy"))]
#[test]
fn nan_entropy_sanitizes_to_zero_in_release() {
    // Pre-fix this returned 0.55 (0.55.min(NaN)); now the NaN collapses to the
    // zero-evidence case → 0.0 keyword-free (NEVER the 0.55 mid-tier floor).
    assert_eq!(entropy_fallback_confidence_for_test(f64::NAN, false), 0.0);
}

#[cfg(not(debug_assertions))]
#[test]
fn nan_confidence_sanitizes_in_release() {
    // Un-anchored: a NaN must not propagate downstream — it collapses to 0.0.
    let unanchored = apply_named_detector_anchor_floor(f64::NAN, false, false);
    assert_eq!(unanchored, 0.0);
    assert!(!unanchored.is_nan());
    // Anchored: the deliberate floor still applies (sanitized-from-0.0 → floor),
    // but the result is a real number, never NaN.
    let anchored = apply_named_detector_anchor_floor(f64::NAN, true, true);
    assert_eq!(anchored, NAMED_DETECTOR_ANCHOR_FLOOR);
    assert!(!anchored.is_nan());
}

//! Gap test: the generic-secret confidence formula.
//!
//! `generic_secret_confidence` is the owner of the generic-emitter base score
//! (context base + entropy boost + length boost, capped at 0.95). The only
//! existing coverage is a source-shape gate that checks the function *exists*;
//! its computed values were never pinned. Pin the exact formula, including the
//! context-base gating: BOTH the entropy boost `((entropy-3.5)*0.1)` and the
//! length boost `((len-16)*0.005)` are clamped to a non-negative range
//! (`[0.0, 0.25]` and `[0.0, 0.15]`), so neither a low-entropy nor a short
//! generic value is penalised below the context base — a deliberate recall
//! floor (policy.rs `generic_secret_confidence`; real low-entropy secrets must
//! keep their base score). A boost only ever ADDS.
//!
//! Boost-zeroing inputs: entropy == 3.5 makes `(entropy - 3.5) * 0.1 == 0`, and
//! value_len == 16 makes `(len - 16) * 0.005 == 0`, so the result is exactly the
//! context base — keeping these assertions off float-rounding fragility.

use keyhog_scanner::testing::generic_secret_confidence_for_test as conf;

#[test]
fn context_base_confidence_and_gating_are_exact() {
    // Ordinary source (Unknown) -> 0.60, regardless of flags.
    assert_eq!(conf("source", false, true, 3.5, 16), 0.60);
    // Comment is 0.30 by default, but lifts to the source floor with --scan-comments.
    assert_eq!(conf("comment", false, false, 3.5, 16), 0.30);
    assert_eq!(conf("comment", true, false, 3.5, 16), 0.60);
    // TestCode/Documentation are haircut ONLY when test paths are penalised;
    // with --no-suppress-test-fixtures they fall back to the source floor.
    assert_eq!(conf("test", false, true, 3.5, 16), 0.25);
    assert_eq!(conf("test", false, false, 3.5, 16), 0.60);
    assert_eq!(conf("doc", false, true, 3.5, 16), 0.30);
    assert_eq!(conf("doc", false, false, 3.5, 16), 0.60);
}

#[test]
fn entropy_and_length_boosts_saturate_at_the_ceiling() {
    // High entropy (boost caps at 0.25) + long value (boost caps at 0.15) push
    // 0.60 + 0.25 + 0.15 = 1.00 past the 0.95 confidence ceiling.
    assert_eq!(conf("source", false, true, 10.0, 100), 0.95);
}

#[test]
fn short_value_gets_no_negative_length_penalty() {
    // value_len 10 (< 16) would make the length term negative, but it clamps to
    // 0, so the result is exactly the un-boosted base (not below it).
    assert_eq!(conf("source", false, true, 3.5, 10), 0.60);
}

#[test]
fn low_entropy_floors_at_the_unboosted_base_never_below() {
    // The entropy boost `((entropy-3.5)*0.1)` is clamped to `[0.0, 0.25]`
    // (policy.rs), so a below-3.5-entropy generic value contributes a ZERO
    // boost — it floors AT the base, never below it. This is the deliberate
    // recall floor: real secrets are frequently low-entropy and must not be
    // penalised under the context base. Mirrors the in-module
    // `low_entropy_never_drives_confidence_below_base` unit test.
    let baseline = conf("source", false, true, 3.5, 16);
    let low_entropy = conf("source", false, true, 1.5, 16);
    assert_eq!(baseline, 0.60);
    assert_eq!(
        low_entropy, baseline,
        "low-entropy generic value must floor at the base (zero boost), not below, got {low_entropy}"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin the base table and a few boost points; these SWEEP the
// formula's STRUCTURAL invariants over the continuous entropy/length domain
// (implementation-independent, NOT an arithmetic mirror): the result never drops
// below the boost-zeroed base (boosts only ADD — the deliberate recall floor) and
// never exceeds the 0.95 ceiling; it is monotone non-decreasing in BOTH entropy and
// value length; and a high-entropy long value under the Unknown base saturates at
// exactly 0.95. Traced against `generic_secret_confidence` (policy.rs). No proptest
// before.

use proptest::prelude::*;

/// Context labels the facade maps (anything not test/comment/doc/assignment →
/// Unknown/source base).
const CONTEXTS: &[&str] = &["source", "comment", "test", "doc", "assignment", "other"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// The result is always within `[base, 0.95]`: boosts only add (never penalise
    /// below the context base) and the ceiling caps at 0.95 — for any context, any
    /// flags, any entropy, any length.
    #[test]
    fn result_stays_between_base_and_ceiling(
        ci in 0usize..CONTEXTS.len(),
        scan_comments in any::<bool>(),
        penalize in any::<bool>(),
        entropy in 0.0f64..12.0,
        len in 0usize..200,
    ) {
        let ctx = CONTEXTS[ci];
        // Boost-zeroed base (entropy 3.5, len 16 make both boost terms 0).
        let base = conf(ctx, scan_comments, penalize, 3.5, 16);
        let out = conf(ctx, scan_comments, penalize, entropy, len);
        prop_assert!(out >= base - 1e-9, "result {out} dropped below base {base}");
        prop_assert!(out <= 0.95 + 1e-9, "result {out} exceeded the 0.95 ceiling");
    }

    /// Monotone non-decreasing in entropy (the entropy boost only ever adds).
    #[test]
    fn monotone_non_decreasing_in_entropy(
        ci in 0usize..CONTEXTS.len(),
        scan_comments in any::<bool>(),
        penalize in any::<bool>(),
        e1 in 0.0f64..12.0,
        e2 in 0.0f64..12.0,
        len in 0usize..200,
    ) {
        let ctx = CONTEXTS[ci];
        let (lo, hi) = if e1 <= e2 { (e1, e2) } else { (e2, e1) };
        let out_lo = conf(ctx, scan_comments, penalize, lo, len);
        let out_hi = conf(ctx, scan_comments, penalize, hi, len);
        prop_assert!(out_lo <= out_hi + 1e-9, "entropy {lo}->{hi} lowered {out_lo}->{out_hi}");
    }

    /// Monotone non-decreasing in value length (the length boost only ever adds).
    #[test]
    fn monotone_non_decreasing_in_length(
        ci in 0usize..CONTEXTS.len(),
        scan_comments in any::<bool>(),
        penalize in any::<bool>(),
        entropy in 0.0f64..12.0,
        l1 in 0usize..200,
        l2 in 0usize..200,
    ) {
        let ctx = CONTEXTS[ci];
        let (lo, hi) = if l1 <= l2 { (l1, l2) } else { (l2, l1) };
        let out_lo = conf(ctx, scan_comments, penalize, entropy, lo);
        let out_hi = conf(ctx, scan_comments, penalize, entropy, hi);
        prop_assert!(out_lo <= out_hi + 1e-9, "len {lo}->{hi} lowered {out_lo}->{out_hi}");
    }

    /// A high-entropy, long value under the Unknown/source base (0.60) saturates the
    /// ceiling at exactly 0.95 (0.60 + 0.25 + 0.15 capped).
    #[test]
    fn high_entropy_long_value_saturates_ceiling(
        scan_comments in any::<bool>(),
        penalize in any::<bool>(),
        entropy in 7.0f64..15.0,
        len in 60usize..300,
    ) {
        prop_assert_eq!(conf("source", scan_comments, penalize, entropy, len), 0.95);
    }
}

//! Gap test: the emit-drop byte-distribution base64 gate's admit policy.
//!
//! `is_byte_distribution_base64_blob` powers the emit-DROP decoy paths
//! (`looks_like_entropy_random_base64_blob_decoy` / `..generic..`). Unlike its
//! penalty-path sibling, it must NOT bite real provider tokens, those are pure
//! base62 (no `+/`, no padding) or carry at most one punctuation mark. So it
//! admits ONLY a genuine byte-distribution signal: both `+` and `/`, or padding
//! with one of them. A uniform random-byte payload almost always produces both;
//! a single-punctuation secret key never should be dropped. This gate had zero
//! direct coverage (pin its exact admit/reject decisions).

use keyhog_scanner::testing::is_byte_distribution_base64_blob_for_test as admits;

#[test]
fn both_punctuation_marks_admit() {
    // 44 chars, length-multiple-of-4, both `+` and `/`: the canonical
    // random-byte-payload shape.
    let value = format!("{}+/", "A".repeat(42));
    assert!(admits(&value, 40, 300));
}

#[test]
fn a_single_punctuation_mark_is_not_dropped() {
    // The load-bearing precision property: a blob with only `+` (or only `/`)
    // and no padding must NOT be admitted, so a single-punctuation secret-key
    // positive survives the emit-drop gate.
    let only_plus = format!("{}+", "A".repeat(43));
    assert!(!admits(&only_plus, 40, 300));
}

#[test]
fn padding_with_one_punctuation_admits() {
    // Padded (`==`) plus one punctuation mark is admitted via the padding clause.
    let value = format!("{}/==", "A".repeat(41));
    assert!(admits(&value, 40, 300));
}

#[test]
fn pure_alphanumeric_blob_is_not_admitted() {
    // No `+`, no `/`, no padding: a base62-shaped token carries no
    // byte-distribution signal and must be rejected.
    let value = "A".repeat(44);
    assert!(!admits(&value, 40, 300));
}

#[test]
fn length_outside_the_band_is_rejected() {
    // Same admitting shape, but below the band floor -> rejected by the length
    // gate before any shape work.
    let value = format!("{}+/", "A".repeat(42)); // 44 chars
    assert!(!admits(&value, 50, 300));
}

#[test]
fn url_safe_alphabet_is_rejected() {
    // `-`/`_` make it url-safe, which `standard_base64_shape` refuses, so the
    // gate cannot fire on a non-standard alphabet.
    let value = format!("{}-_", "A".repeat(42));
    assert!(!admits(&value, 40, 300));
}

#[test]
fn unpadded_non_multiple_of_four_is_rejected() {
    // 43 chars: both punctuation marks present, but neither padded nor a
    // multiple of four, so the structural pre-gate rejects it.
    let value = format!("{}+/", "A".repeat(41));
    assert!(!admits(&value, 40, 300));
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors sample single points of the admit/reject boundary; these
// SWEEP the one-directional guarantees that keep this emit-DROP decoy gate from
// eating real secrets. Each was confirmed against the source
// (`is_byte_distribution_base64_blob`): a length-band pre-gate, then
// `standard_base64_shape` (None on any url-safe char), then a structural
// mult-4/padding pre-gate, then the `(+ && /) || (pad && (+ || /))` admit clause.
// No proptest covered this before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// PRECISION JEWEL: a pure base62 blob (`[A-Za-z0-9]`, no `+`/`/`, no padding)
    /// carries NO byte-distribution signal, so it must NEVER be admitted, the
    /// admit clause needs `+`&`/` or padding+one, none of which a base62 provider
    /// token has. A regression here would silently DROP real base62-shaped keys.
    /// Holds for any in-band length and either reject path (structural OR clause).
    #[test]
    fn pure_alphanumeric_blobs_are_never_admitted(
        value in "[A-Za-z0-9]{20,80}",
    ) {
        prop_assert!(!admits(&value, 1, 1000));
    }

    /// A single url-safe char (`-`/`_`) makes `standard_base64_shape` return
    /// `None` (`has_urlsafe` short-circuit), so the gate cannot fire on a
    /// non-standard alphabet (a url-safe-encoded secret is never dropped here).
    #[test]
    fn url_safe_alphabet_blobs_are_never_admitted(
        rest in "[A-Za-z0-9+/]{20,80}",
    ) {
        let value = format!("-{rest}");
        prop_assert!(!admits(&value, 1, 1000));
    }

    /// LENGTH PRE-GATE: a value below the band floor is rejected before any shape
    /// work, no matter how admitting its shape would otherwise be (`min = len+1`
    /// forces `len < min`).
    #[test]
    fn below_band_floor_is_always_rejected(
        value in "[A-Za-z0-9+/=]{0,80}",
    ) {
        let min = value.len() + 1;
        prop_assert!(!admits(&value, min, min + 100));
    }

    /// The gate must never panic on arbitrary Unicode input or band bounds.
    #[test]
    fn admit_gate_never_panics(
        value in "(?s).{0,60}",
        min in 0usize..200,
        span in 0usize..400,
    ) {
        let _ = admits(&value, min, min + span);
    }
}

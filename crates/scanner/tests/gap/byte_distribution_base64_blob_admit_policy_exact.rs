//! Gap test: the emit-drop byte-distribution base64 gate's admit policy.
//!
//! `is_byte_distribution_base64_blob` powers the emit-DROP decoy paths
//! (`looks_like_entropy_random_base64_blob_decoy` / `..generic..`). Unlike its
//! penalty-path sibling, it must NOT bite real provider tokens — those are pure
//! base62 (no `+/`, no padding) or carry at most one punctuation mark. So it
//! admits ONLY a genuine byte-distribution signal: both `+` and `/`, or padding
//! with one of them. A uniform random-byte payload almost always produces both;
//! a single-punctuation secret key never should be dropped. This gate had zero
//! direct coverage — pin its exact admit/reject decisions.

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

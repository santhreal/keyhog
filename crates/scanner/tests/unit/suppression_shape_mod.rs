use super::*;

#[test]
fn high_entropy_punctuation_payload_pivots_on_shared_cutoff() {
    // 40-char standard-base64 value carrying a `+`; the only thing that
    // decides the verdict is the entropy comparison against the shared
    // HIGH_ENTROPY_BASE64_CUTOFF, so this pins that decision.rs and this gate
    // read the SAME boundary (no re-pasted bare `4.8`).
    let value = format!("{}+", "a".repeat(39));
    assert_eq!(value.len(), 40);
    // Just below the cutoff: not a high-entropy punctuation payload.
    assert!(!looks_like_high_entropy_punctuation_payload(
        &value,
        HIGH_ENTROPY_BASE64_CUTOFF - 0.1
    ));
    // Exactly AT the cutoff: the `+` arm fires.
    assert!(looks_like_high_entropy_punctuation_payload(
        &value,
        HIGH_ENTROPY_BASE64_CUTOFF
    ));
}

#[test]
fn high_entropy_punctuation_payload_requires_length_floor() {
    // 39-char value at/above the cutoff and carrying `+` is still below the
    // 40-byte length floor, so the gate stays closed.
    let short = format!("{}+", "a".repeat(38));
    assert_eq!(short.len(), 39);
    assert!(!looks_like_high_entropy_punctuation_payload(
        &short,
        HIGH_ENTROPY_BASE64_CUTOFF
    ));
}

#[test]
fn uuid_v4_substring_matches_embedded_uuid_via_dash_anchor() {
    // The memchr dash-anchored scan must still find a UUID embedded after a
    // prefix (bat-go `TOKEN_LIST=<uuid>` case) at a non-zero offset.
    assert!(contains_uuid_v4_substring(
        "TOKEN_LIST=636765a9-1f92-4b40-ab0b-85ebd1e2c23d"
    ));
    // Bare UUID at offset 0.
    assert!(contains_uuid_v4_substring(
        "636765a9-1f92-4b40-ab0b-85ebd1e2c23d"
    ));
    // Trailing junk after the UUID.
    assert!(contains_uuid_v4_substring(
        "636765a9-1f92-4b40-ab0b-85ebd1e2c23d;more"
    ));
}

#[test]
fn uuid_v4_substring_rejects_non_uuid_dash_shapes() {
    // Dashes present but not at UUID offsets, and a near-miss with a
    // non-hex byte where a hex digit is required.
    assert!(!contains_uuid_v4_substring(
        "not-a-uuid-value-here-at-all-x"
    ));
    assert!(!contains_uuid_v4_substring(
        "636765a9-1f92-4b40-ab0b-85ebd1e2c23z"
    ));
    // Too short to contain a 36-byte UUID.
    assert!(!contains_uuid_v4_substring("636765a9-1f92-4b40"));
}

#[test]
fn word_separated_identifier_rejects_long_word_single_pass() {
    // `12345678901` is an 11-char word (> max 10) so the identifier gate
    // stays closed; `s3_secret_access_key` is all short words → identifier.
    assert!(looks_like_word_separated_identifier("s3_secret_access_key"));
    assert!(!looks_like_word_separated_identifier(
        "prefix_12345678901xx"
    ));
    // Empty word (`foo__bar`) and pure-digit word both reject.
    assert!(!looks_like_word_separated_identifier("foo__bar_alpha"));
    assert!(!looks_like_word_separated_identifier("alpha_12345_beta"));
}

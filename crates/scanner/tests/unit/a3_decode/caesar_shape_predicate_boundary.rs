//! `candidate_shape_invariant` and `caesar_credential_shape_gate` share ONE structural
//! predicate (`has_digit_and_long_alnum_run`: >=1 ASCII digit AND an 8+
//! contiguous ASCII-alphanumeric run). This pins the exact run-length boundary,
//! the digit requirement, the contiguity requirement, and the shift-invariance
//! that justifies evaluating the shared half once on the raw candidate, so the
//! two callers can never drift on the thresholds after the DEDUP.

use keyhog_scanner::testing::decode_caesar::{
    caesar_credential_shape_gate, caesar_shift, candidate_shape_invariant, KNOWN_PREFIXES,
};

#[test]
fn caesar_shape_predicates_share_exact_digit_and_run_boundary() {
    // ── candidate_shape_invariant: >=1 letter AND >=1 digit AND 8+ alnum run ──

    // 7 letters + 1 digit = a contiguous run of exactly 8 alnum -> passes.
    assert!(candidate_shape_invariant("abcdefg1"));
    // 6 letters + 1 digit = run of 7 -> below MIN_ALNUM_RUN (8) -> fails.
    assert!(!candidate_shape_invariant("abcdef1"));
    // 8 letters but NO digit -> fails the digit half.
    assert!(!candidate_shape_invariant("abcdefgh"));
    // 8 DIGITS, no letter -> the run/digit half passes but the letter
    // requirement (a shift needs a letter to do anything) fails.
    assert!(!candidate_shape_invariant("12345678"));
    // digit + letters present but the longest CONTIGUOUS run is 4 (separators
    // reset the run) -> fails: contiguity is required, not a total count.
    assert!(!candidate_shape_invariant("abc-defg-1234"));

    // ── caesar_credential_shape_gate = the shared shape AND a KNOWN_PREFIXES hit ──

    // AKIA is a known provider prefix; AKIA1234ABCD has a digit and a 12-char
    // alnum run -> shaped.
    assert!(caesar_credential_shape_gate("AKIA1234ABCD"));
    // Same prefix + long run but NO digit -> the shared half rejects it.
    assert!(!caesar_credential_shape_gate("AKIAABCDEFGH"));

    // The two predicates differ ONLY by the KNOWN_PREFIXES gate: a value that
    // passes the shared shape but carries no known prefix is candidate-shaped
    // (worth trying shifts) yet not itself credential-shaped.
    const NO_PREFIX: &str = "qzqz1234qzqz";
    assert!(
        (&*KNOWN_PREFIXES)
            .iter()
            .all(|p| !NO_PREFIX.contains(p.as_str())),
        "test fixture must contain no known prefix, else the assertion below is vacuous"
    );
    assert!(candidate_shape_invariant(NO_PREFIX));
    assert!(!caesar_credential_shape_gate(NO_PREFIX));
}

#[test]
fn candidate_shape_invariant_is_invariant_under_every_caesar_shift() {
    // The shared shape (digit + alnum run + has-letter) is preserved by
    // caesar_shift (letters->letters, digits/punctuation fixed), so evaluating
    // it ONCE on the raw candidate is sound for all 25 shifts. Prove it.
    for sample in [
        "AKIA1234ABCD",
        "abcdefg1",
        "abc-defg-1234",
        "12345678",
        "abcdefgh",
    ] {
        let raw = candidate_shape_invariant(sample);
        for k in 1..=25u8 {
            assert_eq!(
                candidate_shape_invariant(&caesar_shift(sample, k)),
                raw,
                "candidate_shape_invariant must be shift-invariant for {sample:?} at shift {k}"
            );
        }
    }
}

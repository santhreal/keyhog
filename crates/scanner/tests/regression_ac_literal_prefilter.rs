//! Regression coverage for the AC-literal "Layer 0" prefilter
//! (`AlphabetScreen`, `crates/scanner/src/alphabet_filter.rs`) framed around the
//! two canonical AC-LITERAL detectors that keyhog anchors on:
//!
//!   * `aws-access-key`     — literal keywords `AKIA` / `ASIA`
//!                            (regex `(?-i)(AKIA|ASIA)[0-9A-Z]{16}\b`)
//!   * `github-classic-pat` — literal keyword `ghp_`
//!                            (regex `ghp_[A-Za-z0-9]{36}\b`)
//!
//! These are LITERAL-bearing detectors (unlike no-literal detectors such as
//! `datadog-api-key` / `twilio-auth-token`, which fire ONLY through Hyperscan and
//! are deliberately NOT exercised here). The screen's contract is exact and
//! recall-load-bearing: a chunk is ADMITTED (`screen(..) == true`) iff it contains
//! at least one byte present in the union of the detector keyword alphabet, and
//! REJECTED (`false`) iff it contains none. A false-negative silently drops the
//! whole chunk from deeper scanning, so every assertion pins a concrete `bool`.
//!
//! HOST-INDEPENDENCE: the screen must return the SAME verdict on the scalar
//! CpuFallback path and on any SIMD (AVX2) path present on the running host.
//! `assert_alphabet_prefilter_backend_parity` asserts that equality internally
//! across every compiled backend and then returns the (backend-independent)
//! verdict, so the admit/reject probes below run through it to prove the result
//! does not depend on the accelerator state of the test host.
//!
//! Ground-truth alphabet for the union set `["AKIA", "ghp_"]` — letters are
//! ASCII case-folded (both `b` and `b ^ 0x20`), the non-letter `_` (0x5F) is
//! exact:
//!     letters (case-insensitive): A a K k I i G g H h P p
//!     non-letter exact:           _ (0x5F)
//! Filler byte `z` (0x7A) and the digits `0..9` are deliberately OUTSIDE this
//! set so a chunk built only from them must be rejected.

use keyhog_scanner::testing::{assert_alphabet_prefilter_backend_parity, AlphabetScreen};

/// Detector ids under test — kept as concrete strings so an assertion message
/// names the exact detector whose literal alphabet a regression would break.
const AWS_ACCESS_KEY: &str = "aws-access-key";
const GITHUB_CLASSIC_PAT: &str = "github-classic-pat";

/// The AWS access-key literal keywords (`aws-access-key`).
fn aws_targets() -> Vec<String> {
    vec!["AKIA".to_string(), "ASIA".to_string()]
}

/// The GitHub classic-PAT literal keyword (`github-classic-pat`).
fn github_targets() -> Vec<String> {
    vec!["ghp_".to_string()]
}

/// Union of both AC-literal detectors' keyword alphabets.
fn union_targets() -> Vec<String> {
    vec!["AKIA".to_string(), "ghp_".to_string()]
}

#[test]
fn aws_full_access_key_id_is_admitted() {
    // A realistic 20-char AWS access key ID (the canonical AWS docs example).
    // It contains 'A','K','I' from the `AKIA` keyword, so the screen must admit.
    let screen = AlphabetScreen::new(&aws_targets());
    let line = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
    assert_eq!(
        screen.screen(line),
        true,
        "{AWS_ACCESS_KEY}: full AKIA key ID must pass the AC-literal screen"
    );
    // Host-independent: scalar and any SIMD backend agree on the admit verdict.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&aws_targets(), line),
        true
    );
}

#[test]
fn github_full_classic_pat_is_admitted() {
    // A shape-valid `ghp_` + 36-char classic PAT. Contains 'g','h','p','_'.
    let screen = AlphabetScreen::new(&github_targets());
    let line = b"token: ghp_16C7e42F292c6912E7710c838347Ae178B4aZZ";
    assert_eq!(
        screen.screen(line),
        true,
        "{GITHUB_CLASSIC_PAT}: full ghp_ PAT must pass the AC-literal screen"
    );
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&github_targets(), line),
        true
    );
}

#[test]
fn union_admits_aws_only_and_github_only_chunks() {
    // A screen compiled from BOTH detectors must admit a chunk carrying only the
    // AWS keyword bytes AND a chunk carrying only the GitHub keyword bytes.
    let screen = AlphabetScreen::new(&union_targets());
    // Only 'K' (from AKIA) present, none of g/h/p/_.
    assert_eq!(screen.screen(b"zzzKzzz"), true);
    // Only '_' and 'g'/'h'/'p' (from ghp_) present, no A/K/I.
    assert_eq!(screen.screen(b"log_path"), true);
    // Disjoint chunk: 'w','o','r','d',' ','0','1' — none in the union alphabet.
    assert_eq!(screen.screen(b"word 01"), false);
}

#[test]
fn chunk_with_no_detector_literal_bytes_is_screened_out() {
    // A clean, secret-free line whose bytes avoid the union alphabet entirely.
    let screen = AlphabetScreen::new(&union_targets());
    // 'z' (0x7A) filler and digits only.
    assert_eq!(screen.screen(b"zzzzzz 1234567890 zzzzzz"), false);
    // Uppercase near-miss of AKIA using non-member letters B,L,O,B.
    assert_eq!(screen.screen(b"BLOB"), false);
    // Cross-checked host-independent verdict.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&union_targets(), b"zzzzzz 1234567890 zzzzzz"),
        false
    );
}

#[test]
fn host_independent_admit_matches_scalar_cpu_fallback() {
    // The parity helper asserts scalar == AVX2 (when present) internally and
    // returns the shared verdict; a `true` here proves the admit does not depend
    // on the host accelerator.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&aws_targets(), b"prefix ASIA-session marker"),
        true
    );
}

#[test]
fn host_independent_reject_matches_scalar_cpu_fallback() {
    // Rejecting corpus: 'q','w','x','y','v','b',' ','0'..'9' none in AWS alphabet
    // {A a K k I i S s}. Backend-independent `false`.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&aws_targets(), b"qwx yvb 0987"),
        false
    );
}

#[test]
fn single_byte_target_and_non_target_bytes() {
    let screen = AlphabetScreen::new(&union_targets());
    // Single literal byte from a keyword -> admit.
    assert_eq!(screen.screen(b"K"), true); // AKIA
    assert_eq!(screen.screen(b"_"), true); // ghp_
                                           // Single non-member byte -> reject.
    assert_eq!(screen.screen(b"z"), false);
    assert_eq!(screen.screen(b"0"), false);
}

#[test]
fn screen_is_recall_safe_superset_of_case_sensitive_regex() {
    // The `aws-access-key` regex is case-SENSITIVE (`(?-i)`), so lowercase "akia"
    // is NOT a real key. The screen, however, case-folds letters and so still
    // ADMITS the lowercase twin — a deliberate recall-safe superset (the screen
    // must never drop a chunk the case-sensitive regex might still hit elsewhere).
    let screen = AlphabetScreen::new(&["AKIA".to_string()]);
    assert_eq!(
        screen.screen(b"lowercase akia here"),
        true,
        "{AWS_ACCESS_KEY}: folded lowercase twin must still be admitted"
    );
    // And the uppercase real prefix is likewise admitted.
    assert_eq!(screen.screen(b"AKIA"), true);
}

#[test]
fn asia_variant_keyword_admitted_and_disjoint_rejected() {
    // `aws-access-key` also anchors on the `ASIA` (temporary credential) keyword.
    let screen = AlphabetScreen::new(&["ASIA".to_string()]);
    // 'S' is unique to ASIA vs AKIA — must be admitted.
    assert_eq!(screen.screen(b"xxSxx"), true);
    // A chunk with none of {A a S s I i} -> reject.
    assert_eq!(screen.screen(b"grpht bdo 09"), false);
}

#[test]
fn github_underscore_in_avx2_remainder_tail_admitted() {
    // 40-byte chunk: the AVX2 path consumes one 32-byte block then a scalar
    // 8-byte remainder. Placing the only literal byte ('_' from ghp_) at index 37
    // forces the remainder branch, and must still admit.
    let screen = AlphabetScreen::new(&github_targets());
    let mut data = vec![b'z'; 40]; // 'z' is outside the ghp_ alphabet
    data[37] = b'_';
    assert_eq!(screen.screen(&data), true);
    // Same length, no literal byte anywhere -> reject.
    let clean = vec![b'z'; 40];
    assert_eq!(screen.screen(&clean), false);
    // Host-independent for the tail-admit case.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&github_targets(), &data),
        true
    );
}

#[test]
fn boundary_exactly_32_bytes_clean_rejected_hit_admitted() {
    // Exactly one AVX2 block, no remainder.
    let screen = AlphabetScreen::new(&union_targets());
    let clean = vec![b'z'; 32];
    assert_eq!(clean.len(), 32);
    assert_eq!(screen.screen(&clean), false);
    // Literal byte 'A' (AKIA) at the final index of the 32-byte block -> admit.
    let mut hit = vec![b'z'; 32];
    hit[31] = b'A';
    assert_eq!(screen.screen(&hit), true);
}

#[test]
fn large_corpus_single_embedded_key_is_host_independent() {
    // A 4 KiB clean buffer with a single AWS literal byte embedded near the end;
    // proves the screen still admits across a multi-block SIMD sweep and that the
    // verdict is backend-independent.
    let mut data = vec![b'z'; 4096];
    data[4090] = b'I'; // 'I' from AKIA/ASIA
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&aws_targets(), &data),
        true
    );
    // The same buffer with the byte scrubbed back to filler -> reject.
    let clean = vec![b'z'; 4096];
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&aws_targets(), &clean),
        false
    );
}

#[test]
fn whitespace_and_digit_only_line_rejected() {
    // Space 0x20, tab 0x09, LF 0x0A, CR 0x0D and digits — none in the union
    // alphabet {A a K k I i G g H h P p _}.
    let screen = AlphabetScreen::new(&union_targets());
    assert_eq!(screen.screen(b"   \t\n\r 1234567890  "), false);
}

#[test]
fn empty_chunk_is_rejected_on_every_backend() {
    let screen = AlphabetScreen::new(&union_targets());
    assert_eq!(screen.screen(b""), false);
    assert_eq!(screen.screen(&[]), false);
    // Backend-independent: empty short-circuits to `false` everywhere.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&union_targets(), b""),
        false
    );
}

#[test]
fn underscore_membership_exact_del_not_folded() {
    // `_` (0x5F) is a non-letter, so ONLY 0x5F is set for `github-classic-pat`;
    // its 0x20-flip 0x7F (DEL) must NOT be admitted — non-letters are never folded.
    let screen = AlphabetScreen::new(&github_targets());
    assert_eq!(screen.screen(b"_"), true);
    assert_eq!(
        screen.screen(&[0x7Fu8]),
        false,
        "{GITHUB_CLASSIC_PAT}: DEL (0x7F) must not be folded in from '_'"
    );
}

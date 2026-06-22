//! Gap-coverage tests for keyhog-core redaction + deduplication.
//!
//! Source of truth read while authoring:
//!   crates/core/src/lib.rs          -> `redact()`
//!   crates/core/src/dedup.rs        -> `dedup_matches`, `dedup_cross_detector`,
//!                                       `DedupScope`, `DedupedMatch`,
//!                                       `is_same_location`, `is_decoder_*`,
//!                                       `merge_companions`, `max_confidence`
//!   crates/core/src/finding.rs      -> `RawMatch`, `MatchLocation`
//!   crates/core/src/spec.rs         -> `Severity` (Info<ClientSafe<Low<Medium<High<Critical>)
//!
//! Every asserted value is derived from that code, not guessed.

use keyhog_core::{
    dedup_cross_detector, dedup_matches, redact, DedupScope, MatchLocation, RawMatch, Severity,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// SHA-256 of a string, mirroring the private `dedup::sha256_hash` so we can
/// assert `credential_hash` exactly and group two matches by hash on purpose.
fn sha256(s: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn loc(
    source: &str,
    file: Option<&str>,
    line: Option<usize>,
    offset: usize,
    commit: Option<&str>,
) -> MatchLocation {
    MatchLocation {
        source: source.into(),
        file_path: file.map(Arc::from),
        line,
        offset,
        commit: commit.map(Arc::from),
        author: None,
        date: None,
    }
}

/// Build a RawMatch with the supplied identity. `credential_hash` is set to the
/// real SHA-256 of `credential` (matching what `dedup_matches` recomputes) so
/// cross-detector grouping behaves as in production.
fn rm(
    detector_id: &str,
    detector_name: &str,
    service: &str,
    severity: Severity,
    credential: &str,
    location: MatchLocation,
    confidence: Option<f64>,
) -> RawMatch {
    RawMatch {
        detector_id: detector_id.into(),
        detector_name: detector_name.into(),
        service: service.into(),
        severity,
        credential: credential.into(),
        credential_hash: sha256(credential),
        companions: HashMap::new(),
        location,
        entropy: None,
        confidence,
    }
}

/// A simple match anchored at a real `filesystem` location in `a.txt`.
fn simple(detector: &str, credential: &str, offset: usize, conf: Option<f64>) -> RawMatch {
    rm(
        detector,
        detector,
        "svc",
        Severity::High,
        credential,
        loc("filesystem", Some("a.txt"), Some(1), offset, None),
        conf,
    )
}

// ===========================================================================
// redact() — boundary: 8 vs 9 chars, no middle exposure (ASCII path)
// ===========================================================================

#[test]
fn redact_empty_is_four_stars_and_borrowed() {
    let out = redact("");
    assert_eq!(out, "****");
    assert!(matches!(out, Cow::Borrowed(_)));
}

#[test]
fn redact_len1_is_four_stars() {
    assert_eq!(redact("a"), "****");
}

#[test]
fn redact_len7_is_four_stars() {
    assert_eq!(redact("ABCDEFG"), "****");
}

#[test]
fn redact_len8_boundary_is_four_stars() {
    // s.len() <= 8 -> "****". 8 is the inclusive upper bound for full masking.
    assert_eq!(redact("ABCDEFGH"), "****");
    // No source byte from the 8-char secret survives.
    let out = redact("S3CR3TXY");
    assert!(!out.contains('S'));
    assert!(!out.contains('Y'));
}

#[test]
fn redact_len9_boundary_reveals_scaled_edges() {
    // First length where the preview branch fires: first 2 + "..." + last 2.
    let out = redact("ABCDEFGHI");
    assert_eq!(out, "AB...HI");
    assert!(matches!(out, Cow::Owned(_)));
    // The middle characters must NOT appear.
    assert!(!out.contains('C'));
    assert!(!out.contains('D'));
    assert!(!out.contains('E'));
}

#[test]
fn redact_len9_no_middle_exposure_distinct_middle() {
    // Distinct middle byte 'X' is the only char that can't appear in output.
    let out = redact("WXYZ@MNOP");
    assert_eq!(out, "WX...OP");
    assert!(!out.contains('@'));
}

#[test]
fn redact_len10_preview_drops_two_middle_bytes() {
    let out = redact("0123456789");
    assert_eq!(out, "01...89");
    assert!(!out.contains('2'));
    assert!(!out.contains('3'));
    assert!(!out.contains('4'));
    assert!(!out.contains('5'));
}

#[test]
fn redact_len11_preview() {
    let out = redact("ABCDEFGHIJK");
    assert_eq!(out, "AB...JK");
}

#[test]
fn redact_long_key_only_endpoints_survive() {
    let secret = "AKIAIOSFODNN7EXAMPLE"; // 20 chars
    let out = redact(secret);
    assert_eq!(out, "AKIA...MPLE");
    // Length of preview is always 11 for any ascii secret > 8 chars.
    assert_eq!(out.len(), 11);
    // The high-entropy middle "IOSFODNN7EXA" is gone.
    assert!(!out.contains("IOSFODNN"));
}

#[test]
fn redact_preview_len_is_always_11_for_ascii_over_8() {
    for s in [
        "123456789",
        "1234567890",
        "abcdefghijklmnopqrstuvwxyz",
        &"Z".repeat(4096),
    ] {
        let out = redact(s);
        let edge = (s.len() / 4).clamp(1, 4);
        assert_eq!(
            out.len(),
            (edge * 2) + 3,
            "ascii >8 should redact to scaled edge windows"
        );
        assert!(out.contains("..."));
    }
}

#[test]
fn redact_first4_and_last4_match_source_slices_ascii() {
    let s = "PREFIXmiddleSUFFIX";
    let out = redact(s);
    assert_eq!(&out[..4], &s[..4]);
    assert_eq!(&out[out.len() - 4..], &s[s.len() - 4..]);
    assert_eq!(out, "PREF...FFIX");
}

#[test]
fn redact_whitespace_and_symbols_preserved_at_edges() {
    // Whitespace at the edges is kept verbatim; redact does not trim.
    let out = redact("  spaces  end!"); // 14 chars
    assert_eq!(out, "  s...nd!");
}

// --- redact() UTF-8 / multibyte path (char_count, not byte len) ------------

#[test]
fn redact_utf8_8_chars_is_four_stars() {
    // 8 multibyte chars: char_count <= 8 -> "****" even though byte len > 8.
    let s = "αβγδεζηθ"; // 8 Greek letters, 16 bytes, not ascii
    assert!(!s.is_ascii());
    assert_eq!(s.chars().count(), 8);
    assert_eq!(redact(s), "****");
}

#[test]
fn redact_utf8_9_chars_preview_by_char_not_byte() {
    let s = "αβγδεζηθι"; // 9 Greek letters
    assert!(!s.is_ascii());
    assert_eq!(s.chars().count(), 9);
    let out = redact(s);
    assert_eq!(out, "αβ...θι");
    assert!(!out.contains('γ'));
    assert!(!out.contains('δ'));
    assert!(!out.contains('ε'));
}

#[test]
fn redact_utf8_does_not_split_on_byte_boundary() {
    // A short multibyte secret whose byte-len > 8 but char-count <= 8 must NOT
    // take the ascii branch (which would byte-slice and panic / mis-split).
    let s = "日本語テスト"; // 6 CJK chars, 18 bytes
    assert!(!s.is_ascii());
    assert_eq!(s.chars().count(), 6);
    assert_eq!(redact(s), "****");
}

#[test]
fn redact_utf8_long_preview_takes_first4_last4_chars() {
    let s = "café_münchen_zürich"; // mixed; not ascii due to é/ü
    assert!(!s.is_ascii());
    let n = s.chars().count();
    let first4: String = s.chars().take(4).collect();
    let last4: String = s.chars().skip(n - 4).collect();
    assert_eq!(redact(s), format!("{first4}...{last4}"));
}

#[test]
fn redact_property_never_leaks_strict_interior_char() {
    // Property: for any secret with >8 chars, every char strictly between
    // index 4 and char_count-4 (i.e. not in first4 or last4) is absent from
    // the rendered preview. (Edge chars may coincidentally repeat interior
    // chars, so we only assert about chars unique to the interior.)
    use proptest::prelude::*;
    let mut runner = proptest::test_runner::TestRunner::default();
    runner
        .run(&proptest::collection::vec(any::<char>(), 9..40), |chars| {
            let s: String = chars.iter().collect();
            let n = s.chars().count();
            prop_assume!(n > 8);
            let out = redact(&s);
            let cv: Vec<char> = s.chars().collect();
            let first4: std::collections::HashSet<char> = cv[..4].iter().copied().collect();
            let last4: std::collections::HashSet<char> = cv[n - 4..].iter().copied().collect();
            for &c in &cv[4..n - 4] {
                if !first4.contains(&c) && !last4.contains(&c) && c != '.' {
                    prop_assert!(
                        !out.contains(c),
                        "interior char {:?} leaked into preview {:?}",
                        c,
                        out
                    );
                }
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn redact_property_short_always_masked() {
    use proptest::prelude::*;
    let mut runner = proptest::test_runner::TestRunner::default();
    runner
        .run(&proptest::collection::vec(any::<char>(), 0..=8), |chars| {
            let s: String = chars.iter().collect();
            prop_assume!(s.chars().count() <= 8);
            prop_assert_eq!(redact(&s), "****");
            Ok(())
        })
        .unwrap();
}

// ===========================================================================
// dedup_matches — DedupScope::None
// ===========================================================================

#[test]
fn dedup_none_preserves_every_match_and_order() {
    let m0 = simple("d", "SECRET_VALUE_LONG", 10, Some(0.5));
    let m1 = simple("d", "SECRET_VALUE_LONG", 20, Some(0.9));
    let m2 = simple("e", "OTHER_VALUE_LONGX", 30, Some(0.1));
    let out = dedup_matches(vec![m0, m1, m2], &DedupScope::None);
    // None == identity map, NO sort, NO collapse.
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].primary_location.offset, 10);
    assert_eq!(out[1].primary_location.offset, 20);
    assert_eq!(out[2].primary_location.offset, 30);
    // additional_locations always empty under None.
    assert!(out.iter().all(|d| d.additional_locations.is_empty()));
}

#[test]
fn dedup_none_computes_real_credential_hash() {
    let m = simple("d", "hunter2hunter2hunter2", 0, None);
    let out = dedup_matches(vec![m], &DedupScope::None);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].credential_hash, sha256("hunter2hunter2hunter2"));
    // confidence passthrough.
    assert_eq!(out[0].confidence, None);
}

#[test]
fn dedup_none_keeps_identical_duplicates_separate() {
    // Two byte-identical matches stay TWO findings under None.
    let a = simple("d", "DUPDUPDUPDUPDUP", 5, Some(0.7));
    let b = simple("d", "DUPDUPDUPDUPDUP", 5, Some(0.7));
    let out = dedup_matches(vec![a, b], &DedupScope::None);
    assert_eq!(out.len(), 2);
}

#[test]
fn dedup_none_empty_input_empty_output() {
    let out = dedup_matches(Vec::new(), &DedupScope::None);
    assert!(out.is_empty());
}

// ===========================================================================
// dedup_matches — DedupScope::Credential (cross-file collapse)
// ===========================================================================

#[test]
fn dedup_credential_collapses_same_secret_across_files() {
    let a = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "API_KEY_VALUE_1234",
        loc("filesystem", Some("a.txt"), Some(1), 10, None),
        Some(0.5),
    );
    let b = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "API_KEY_VALUE_1234",
        loc("filesystem", Some("b.txt"), Some(9), 99, None),
        Some(0.5),
    );
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    // Different file => not is_same_location => recorded as additional.
    assert_eq!(out[0].additional_locations.len(), 1);
}

#[test]
fn dedup_credential_primary_is_lowest_offset_within_file() {
    // Pre-sort by (file, offset). Lowest-offset same-file entry becomes primary;
    // higher offset, DIFFERENT line => additional (not same-location).
    let lo = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "TOKENTOKENTOKENTOKEN",
        loc("filesystem", Some("a.txt"), Some(1), 5, None),
        Some(0.5),
    );
    let hi = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "TOKENTOKENTOKENTOKEN",
        loc("filesystem", Some("a.txt"), Some(2), 500, None),
        Some(0.5),
    );
    // Feed in reverse (hi first) — sort must still pick offset 5 as primary.
    let out = dedup_matches(vec![hi, lo], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].primary_location.offset, 5);
    assert_eq!(out[0].primary_location.line, Some(1));
    assert_eq!(out[0].additional_locations.len(), 1);
    assert_eq!(out[0].additional_locations[0].offset, 500);
}

#[test]
fn dedup_credential_same_file_same_line_collapses_no_additional() {
    // is_same_location ignores offset: same (source,file,line,commit) =>
    // synthetic-alias drop, NO additional location recorded.
    let real = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "ENVSECRETENVSECRET",
        loc("filesystem", Some(".env"), Some(1), 27, None),
        Some(0.6),
    );
    let synthetic = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "ENVSECRETENVSECRET",
        loc("filesystem", Some(".env"), Some(1), 80, None), // past-EOF synthetic
        Some(0.6),
    );
    let out = dedup_matches(vec![real, synthetic], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    // Lowest offset (27) is primary; the line-1 alias at 80 is dropped, not added.
    assert_eq!(out[0].primary_location.offset, 27);
    assert!(
        out[0].additional_locations.is_empty(),
        "same (file,line) alias must not create '+1 more locations'"
    );
}

#[test]
fn dedup_credential_distinct_secrets_stay_separate() {
    let a = simple("d", "SECRET_ALPHA_VALUE", 1, Some(0.5));
    let b = simple("d", "SECRET_BETA_VALUEX", 2, Some(0.5));
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);
    assert_eq!(out.len(), 2);
}

#[test]
fn dedup_credential_distinct_detectors_same_value_stay_separate() {
    // Key is (detector_id, credential, None) — different detector => separate.
    let a = simple("google-api", "AIzaSyValueHere1234", 1, Some(0.5));
    let b = simple("google-maps", "AIzaSyValueHere1234", 1, Some(0.5));
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);
    assert_eq!(out.len(), 2);
}

#[test]
fn dedup_credential_confidence_is_max_across_group() {
    let lo = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "CONFVALUECONFVALUE",
        loc("filesystem", Some("a.txt"), Some(1), 10, None),
        Some(0.30),
    );
    let hi = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "CONFVALUECONFVALUE",
        loc("filesystem", Some("b.txt"), Some(1), 10, None),
        Some(0.95),
    );
    let out = dedup_matches(vec![lo, hi], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].confidence, Some(0.95));
}

#[test]
fn dedup_credential_confidence_max_handles_none() {
    // max_confidence(None, Some) == Some; first seen None then Some(0.4).
    let none_conf = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "MIXEDCONFMIXEDCONF",
        loc("filesystem", Some("a.txt"), Some(1), 1, None),
        None,
    );
    let some_conf = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "MIXEDCONFMIXEDCONF",
        loc("filesystem", Some("b.txt"), Some(1), 1, None),
        Some(0.4),
    );
    let out = dedup_matches(vec![none_conf, some_conf], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].confidence, Some(0.4));
}

#[test]
fn dedup_credential_output_sorted_by_key_deterministic() {
    // Output Vec is sorted by DedupKey == (detector_id, credential, None).
    // Insert in non-sorted order; assert detector_id ascending in output.
    let m_z = simple("zeta", "ZVALUEZVALUEZVALUE", 1, Some(0.5));
    let m_a = simple("alpha", "AVALUEAVALUEAVALUE", 1, Some(0.5));
    let m_m = simple("mu", "MVALUEMVALUEMVALUE", 1, Some(0.5));
    let out = dedup_matches(vec![m_z, m_a, m_m], &DedupScope::Credential);
    let ids: Vec<&str> = out.iter().map(|d| d.detector_id.as_ref()).collect();
    assert_eq!(ids, vec!["alpha", "mu", "zeta"]);
}

#[test]
fn dedup_credential_three_files_two_additional_locations() {
    let mk = |file: &str, line: usize| {
        rm(
            "d",
            "D",
            "svc",
            Severity::High,
            "TRIPLEFILESECRETXX",
            loc("filesystem", Some(file), Some(line), 1, None),
            Some(0.5),
        )
    };
    let out = dedup_matches(
        vec![mk("c.txt", 3), mk("a.txt", 1), mk("b.txt", 2)],
        &DedupScope::Credential,
    );
    assert_eq!(out.len(), 1);
    // Primary picked by file_path sort: "a.txt" wins.
    assert_eq!(out[0].primary_location.file_path.as_deref(), Some("a.txt"));
    assert_eq!(out[0].additional_locations.len(), 2);
}

// ===========================================================================
// dedup_matches — DedupScope::File (per-file grouping)
// ===========================================================================

#[test]
fn dedup_file_same_secret_different_files_stay_separate() {
    let a = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "FILESCOPESECRETXXXX",
        loc("filesystem", Some("a.txt"), Some(1), 10, None),
        Some(0.5),
    );
    let b = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "FILESCOPESECRETXXXX",
        loc("filesystem", Some("b.txt"), Some(1), 10, None),
        Some(0.5),
    );
    // File scope: file is part of the key => two distinct findings.
    let out = dedup_matches(vec![a, b], &DedupScope::File);
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|d| d.additional_locations.is_empty()));
}

#[test]
fn dedup_file_same_secret_same_file_different_line_collapses() {
    let l1 = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "SAMEFILESECRETXXXXX",
        loc("filesystem", Some("a.txt"), Some(1), 10, None),
        Some(0.5),
    );
    let l2 = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "SAMEFILESECRETXXXXX",
        loc("filesystem", Some("a.txt"), Some(7), 200, None),
        Some(0.5),
    );
    let out = dedup_matches(vec![l1, l2], &DedupScope::File);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].primary_location.offset, 10);
    assert_eq!(out[0].additional_locations.len(), 1);
    assert_eq!(out[0].additional_locations[0].line, Some(7));
}

#[test]
fn dedup_file_identity_separates_by_source_backend() {
    // File-scope identity is `(source, file_path, commit)`. Same file path but
    // different source backend => different group.
    let fs = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "SRCSPLITSECRETXXXXX",
        loc("filesystem", Some("shared"), Some(1), 1, None),
        Some(0.5),
    );
    let git = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "SRCSPLITSECRETXXXXX",
        loc("git", Some("shared"), Some(1), 1, None),
        Some(0.5),
    );
    let out = dedup_matches(vec![fs, git], &DedupScope::File);
    assert_eq!(out.len(), 2);
}

#[test]
fn dedup_file_identity_separates_by_commit() {
    let c1 = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "COMMITSPLITSECRETXX",
        loc("git", Some("f"), Some(1), 1, Some("aaa")),
        Some(0.5),
    );
    let c2 = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "COMMITSPLITSECRETXX",
        loc("git", Some("f"), Some(1), 1, Some("bbb")),
        Some(0.5),
    );
    let out = dedup_matches(vec![c1, c2], &DedupScope::File);
    assert_eq!(out.len(), 2);
}

#[test]
fn dedup_file_none_path_uses_structured_none_and_collapses() {
    // file_path None stays a structured None; two None-path matches in the same
    // source+commit collapse, different LINE => one additional.
    let a = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "NOPATHSECRETNOPATHX",
        loc("filesystem", None, Some(1), 1, None),
        Some(0.5),
    );
    let b = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "NOPATHSECRETNOPATHX",
        loc("filesystem", None, Some(2), 9, None),
        Some(0.5),
    );
    let out = dedup_matches(vec![a, b], &DedupScope::File);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].additional_locations.len(), 1);
}

// ===========================================================================
// dedup_matches — decoder-alias preference (is_decoder_alias_pair)
// ===========================================================================

#[test]
fn dedup_decoder_alias_original_replaces_decoder_primary_by_line() {
    // Decoder location seen first (lower offset after sort) -> becomes primary;
    // then the non-decoder original within line abs_diff<=1 REPLACES it.
    let decoded = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "DECODEDSECRETXXXXXX",
        loc("filesystem/base64", Some("f"), Some(5), 100, None),
        Some(0.5),
    );
    let original = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "DECODEDSECRETXXXXXX",
        loc("filesystem", Some("f"), Some(6), 200, None),
        Some(0.5),
    );
    let out = dedup_matches(vec![decoded, original], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].primary_location.source.as_ref(), "filesystem");
    assert!(out[0].additional_locations.is_empty());
}

#[test]
fn dedup_decoder_alias_by_offset_within_16() {
    // line None on both -> falls through to offset abs_diff<=16 check.
    let decoded = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "OFFSETALIASSECRETXX",
        loc("filesystem/hex", Some("f"), None, 50, None),
        Some(0.5),
    );
    let original = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "OFFSETALIASSECRETXX",
        loc("filesystem", Some("f"), None, 60, None), // diff 10 <= 16
        Some(0.5),
    );
    let out = dedup_matches(vec![decoded, original], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].primary_location.source.as_ref(), "filesystem");
    assert!(out[0].additional_locations.is_empty());
}

#[test]
fn dedup_decoder_alias_offset_gap_over_16_is_additional_not_alias() {
    // Offset diff 17 (>16) and no line info -> NOT an alias pair. The decoder
    // entry (lower offset, sorted first) is primary; original becomes additional.
    let decoded = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "FARGAPSECRETXXXXXXX",
        loc("filesystem/hex", Some("f"), None, 10, None),
        Some(0.5),
    );
    let original = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "FARGAPSECRETXXXXXXX",
        loc("filesystem", Some("f"), None, 27, None), // diff 17 > 16
        Some(0.5),
    );
    let out = dedup_matches(vec![decoded, original], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    // Not an alias -> not same-location (sources differ) -> recorded additional.
    assert_eq!(out[0].primary_location.source.as_ref(), "filesystem/hex");
    assert_eq!(out[0].additional_locations.len(), 1);
}

#[test]
fn dedup_decoder_alias_two_decoders_not_a_pair() {
    // is_decoder_alias_pair requires exactly one side to be a decoder. Two
    // decoder locations are not an alias pair.
    let b64 = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "TWODECODERSECRETXXX",
        loc("filesystem/base64", Some("f"), Some(1), 5, None),
        Some(0.5),
    );
    let hex = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "TWODECODERSECRETXXX",
        loc("filesystem/hex", Some("f"), Some(1), 6, None),
        Some(0.5),
    );
    let out = dedup_matches(vec![b64, hex], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    // Same (source? no — sources differ) but same (file,line) => is_same_location
    // is false because `source` differs, yet not alias-pair. Both line 1 same
    // file: is_same_location compares source too, so they are NOT same loc, and
    // not an alias pair => second becomes additional.
    assert_eq!(out[0].additional_locations.len(), 1);
}

#[test]
fn dedup_decoder_alias_does_not_demote_when_existing_is_original() {
    // Existing primary is non-decoder original; incoming is decoder alias.
    // Branch: is_decoder_location(existing)==false so primary is NOT replaced,
    // and the alias is merged (continue) -> no additional location.
    let original = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "KEEPORIGINALSECRETX",
        loc("filesystem", Some("f"), Some(2), 10, None),
        Some(0.5),
    );
    let decoded = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "KEEPORIGINALSECRETX",
        loc("filesystem/json", Some("f"), Some(3), 200, None),
        Some(0.5),
    );
    // original sorts first (offset 10 < 200) -> primary; decoded is the alias.
    let out = dedup_matches(vec![original, decoded], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].primary_location.source.as_ref(), "filesystem");
    assert!(out[0].additional_locations.is_empty());
}

#[test]
fn dedup_decoder_alias_merges_confidence_max() {
    let decoded = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "ALIASCONFSECRETXXXX",
        loc("filesystem/url", Some("f"), Some(1), 5, None),
        Some(0.2),
    );
    let original = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "ALIASCONFSECRETXXXX",
        loc("filesystem", Some("f"), Some(1), 6, None),
        Some(0.88),
    );
    let out = dedup_matches(vec![decoded, original], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].confidence, Some(0.88));
}

#[test]
fn dedup_decoder_alias_different_file_not_a_pair() {
    // is_decoder_alias_pair returns false if file_path differs.
    let decoded = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "DIFFFILEALIASSECRET",
        loc("filesystem/hex", Some("a"), Some(1), 5, None),
        Some(0.5),
    );
    let original = rm(
        "d",
        "D",
        "svc",
        Severity::High,
        "DIFFFILEALIASSECRET",
        loc("filesystem", Some("b"), Some(1), 6, None),
        Some(0.5),
    );
    let out = dedup_matches(vec![decoded, original], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    // Sorted by file_path: "a" < "b" so decoder ("a") is primary; original is additional.
    assert_eq!(out[0].primary_location.file_path.as_deref(), Some("a"));
    assert_eq!(out[0].additional_locations.len(), 1);
}

// ===========================================================================
// dedup_matches — companion merging
// ===========================================================================

#[test]
fn dedup_companions_merge_distinct_keys() {
    let mut a = simple("d", "COMPANIONSECRETXXXX", 1, Some(0.5));
    a.companions.insert("region".into(), "us-east".into());
    let mut b = simple("d", "COMPANIONSECRETXXXX", 1, Some(0.5));
    b.location = loc("filesystem", Some("b.txt"), Some(1), 1, None);
    b.companions.insert("account".into(), "1234".into());
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].companions.get("region").map(String::as_str),
        Some("us-east")
    );
    assert_eq!(
        out[0].companions.get("account").map(String::as_str),
        Some("1234")
    );
}

#[test]
fn dedup_companions_merge_conflicting_value_joins_with_pipe() {
    let mut a = simple("d", "PIPEJOINSECRETXXXXX", 1, Some(0.5));
    a.companions.insert("env".into(), "prod".into());
    let mut b = simple("d", "PIPEJOINSECRETXXXXX", 1, Some(0.5));
    b.location = loc("filesystem", Some("b.txt"), Some(1), 1, None);
    b.companions.insert("env".into(), "staging".into());
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    // merge_companions joins differing values with " | ".
    assert_eq!(
        out[0].companions.get("env").map(String::as_str),
        Some("prod | staging")
    );
}

#[test]
fn dedup_companions_merge_identical_value_no_duplicate() {
    let mut a = simple("d", "SAMECOMPSECRETXXXXX", 1, Some(0.5));
    a.companions.insert("env".into(), "prod".into());
    let mut b = simple("d", "SAMECOMPSECRETXXXXX", 1, Some(0.5));
    b.location = loc("filesystem", Some("b.txt"), Some(1), 1, None);
    b.companions.insert("env".into(), "prod".into());
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    // Identical value -> Some(_) arm does nothing; stays "prod".
    assert_eq!(
        out[0].companions.get("env").map(String::as_str),
        Some("prod")
    );
}

#[test]
fn dedup_companions_merge_idempotent_already_present_segment() {
    // Pre-existing "prod | staging"; incoming "staging" already a segment ->
    // not re-appended.
    let mut a = simple("d", "IDEMPSECRETXXXXXXXX", 1, Some(0.5));
    a.companions.insert("env".into(), "prod | staging".into());
    let mut b = simple("d", "IDEMPSECRETXXXXXXXX", 1, Some(0.5));
    b.location = loc("filesystem", Some("b.txt"), Some(1), 1, None);
    b.companions.insert("env".into(), "staging".into());
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);
    assert_eq!(
        out[0].companions.get("env").map(String::as_str),
        Some("prod | staging")
    );
}

// ===========================================================================
// dedup_cross_detector — winner by confidence, then severity, then id
// ===========================================================================

#[test]
fn cross_detector_single_input_passthrough() {
    // len() < 2 short-circuit returns input unchanged.
    let m = simple("only", "SINGLEXDETSECRETXXX", 1, Some(0.5));
    let deduped = dedup_matches(vec![m], &DedupScope::Credential);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1);
    assert!(out[0].companions.is_empty());
}

#[test]
fn cross_detector_winner_by_highest_confidence() {
    // Same credential value & same file => one cross-detector group.
    let cred = "AIzaSyCrossDetector1";
    let lo = rm(
        "google-maps",
        "Google Maps",
        "maps",
        Severity::High,
        cred,
        loc("filesystem", Some("f"), Some(1), 1, None),
        Some(0.40),
    );
    let hi = rm(
        "google-api",
        "Google API",
        "google",
        Severity::High,
        cred,
        loc("filesystem", Some("f"), Some(1), 1, None),
        Some(0.90),
    );
    // First-pass keeps detectors separate (distinct detector_id keys).
    let deduped = dedup_matches(vec![lo, hi], &DedupScope::Credential);
    assert_eq!(deduped.len(), 2);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1, "two detectors on one credential fold to one");
    // Winner = highest confidence = google-api (0.90).
    assert_eq!(out[0].detector_id.as_ref(), "google-api");
    assert_eq!(out[0].confidence, Some(0.90));
    // Loser folded into companions under cross_detector.0.
    let folded = out[0].companions.get("cross_detector.0").unwrap();
    assert!(folded.contains("maps"));
    assert!(folded.contains("Google Maps"));
    assert!(folded.contains("[0.40]"));
}

#[test]
fn cross_detector_tiebreak_by_severity_when_confidence_equal() {
    let cred = "EQUALCONFDIFFSEVXXXX";
    let crit = rm(
        "det-crit",
        "Crit",
        "csvc",
        Severity::Critical,
        cred,
        loc("filesystem", Some("f"), Some(1), 1, None),
        Some(0.5),
    );
    let low = rm(
        "det-low",
        "Low",
        "lsvc",
        Severity::Low,
        cred,
        loc("filesystem", Some("f"), Some(1), 1, None),
        Some(0.5),
    );
    let deduped = dedup_matches(vec![low, crit], &DedupScope::Credential);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1);
    // Equal confidence -> higher severity (Critical) wins.
    assert_eq!(out[0].detector_id.as_ref(), "det-crit");
    assert_eq!(out[0].severity, Severity::Critical);
}

#[test]
fn cross_detector_tiebreak_by_detector_id_when_conf_and_sev_equal() {
    let cred = "ALLEQUALTIEBREAKXXXX";
    let a = rm(
        "aaa-detector",
        "A",
        "asvc",
        Severity::Medium,
        cred,
        loc("filesystem", Some("f"), Some(1), 1, None),
        Some(0.7),
    );
    let z = rm(
        "zzz-detector",
        "Z",
        "zsvc",
        Severity::Medium,
        cred,
        loc("filesystem", Some("f"), Some(1), 1, None),
        Some(0.7),
    );
    let deduped = dedup_matches(vec![z, a], &DedupScope::Credential);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1);
    // Equal conf+sev -> lexicographically smallest detector_id wins.
    assert_eq!(out[0].detector_id.as_ref(), "aaa-detector");
}

#[test]
fn cross_detector_none_confidence_treated_as_zero() {
    let cred = "NONECONFVSSOMEXXXXXX";
    let none_conf = rm(
        "det-none",
        "None",
        "nsvc",
        Severity::Critical, // higher severity but conf treated as 0.0
        cred,
        loc("filesystem", Some("f"), Some(1), 1, None),
        None,
    );
    let some_conf = rm(
        "det-some",
        "Some",
        "ssvc",
        Severity::Low,
        cred,
        loc("filesystem", Some("f"), Some(1), 1, None),
        Some(0.10),
    );
    let deduped = dedup_matches(vec![none_conf, some_conf], &DedupScope::Credential);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1);
    // conf None -> 0.0 < 0.10, so det-some wins despite lower severity.
    assert_eq!(out[0].detector_id.as_ref(), "det-some");
    // Loser (det-none) confidence renders as "n/a".
    let folded = out[0].companions.get("cross_detector.0").unwrap();
    assert!(
        folded.contains("[n/a]"),
        "None confidence must render n/a, got {folded}"
    );
}

#[test]
fn cross_detector_three_losers_indexed_in_confidence_order() {
    let cred = "THREELOSERSSECRETXXX";
    let mk = |id: &str, conf: f64| {
        rm(
            id,
            id,
            id,
            Severity::High,
            cred,
            loc("filesystem", Some("f"), Some(1), 1, None),
            Some(conf),
        )
    };
    // winner 0.9; losers 0.7, 0.5, 0.3 in descending order.
    let deduped = dedup_matches(
        vec![mk("d3", 0.3), mk("d1", 0.9), mk("d2", 0.7), mk("d4", 0.5)],
        &DedupScope::Credential,
    );
    assert_eq!(deduped.len(), 4);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].detector_id.as_ref(), "d1"); // 0.9 winner
                                                   // cross_detector.0 = 0.7 (d2), .1 = 0.5 (d4), .2 = 0.3 (d3).
    assert!(out[0]
        .companions
        .get("cross_detector.0")
        .unwrap()
        .contains("0.70"));
    assert!(out[0]
        .companions
        .get("cross_detector.1")
        .unwrap()
        .contains("0.50"));
    assert!(out[0]
        .companions
        .get("cross_detector.2")
        .unwrap()
        .contains("0.30"));
    assert!(out[0].companions.get("cross_detector.3").is_none());
}

#[test]
fn cross_detector_different_files_not_grouped() {
    // GroupKey includes primary_location.file_path. Same hash, different files
    // => not folded.
    let cred = "DIFFFILEXDETSECRETXX";
    let a = rm(
        "google-api",
        "A",
        "g",
        Severity::High,
        cred,
        loc("filesystem", Some("a.txt"), Some(1), 1, None),
        Some(0.9),
    );
    let b = rm(
        "google-maps",
        "B",
        "m",
        Severity::High,
        cred,
        loc("filesystem", Some("b.txt"), Some(1), 1, None),
        Some(0.5),
    );
    let deduped = dedup_matches(vec![a, b], &DedupScope::Credential);
    let out = dedup_cross_detector(deduped);
    // Different file_path keys -> stay separate.
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|d| {
        d.companions
            .keys()
            .all(|k| !k.starts_with("cross_detector"))
    }));
}

#[test]
fn cross_detector_different_credentials_not_grouped() {
    // Different credential hashes (even same detector ids would differ) -> separate.
    let a = rm(
        "google-api",
        "A",
        "g",
        Severity::High,
        "AIzaCREDENTIALONEXXX",
        loc("filesystem", Some("f"), Some(1), 1, None),
        Some(0.9),
    );
    let b = rm(
        "google-maps",
        "B",
        "m",
        Severity::High,
        "AIzaCREDENTIALTWOXXX",
        loc("filesystem", Some("f"), Some(1), 1, None),
        Some(0.5),
    );
    let deduped = dedup_matches(vec![a, b], &DedupScope::Credential);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 2);
}

#[test]
fn cross_detector_output_sorted_by_detector_id_then_hash() {
    // Two independent (ungrouped) credentials -> output sorted by detector_id.
    let a = rm(
        "zzz-det",
        "Z",
        "z",
        Severity::High,
        "ZZZCREDENTIALVALUEXX",
        loc("filesystem", Some("z.txt"), Some(1), 1, None),
        Some(0.5),
    );
    let b = rm(
        "aaa-det",
        "A",
        "a",
        Severity::High,
        "AAACREDENTIALVALUEXX",
        loc("filesystem", Some("a.txt"), Some(1), 1, None),
        Some(0.5),
    );
    let deduped = dedup_matches(vec![a, b], &DedupScope::Credential);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 2);
    let ids: Vec<&str> = out.iter().map(|d| d.detector_id.as_ref()).collect();
    assert_eq!(ids, vec!["aaa-det", "zzz-det"]);
}

#[test]
fn cross_detector_preserves_winner_existing_companions() {
    // Winner already has a companion; loser folds in WITHOUT clobbering it.
    let cred = "WINNERCOMPSECRETXXXX";
    let mut hi = rm(
        "google-api",
        "API",
        "google",
        Severity::High,
        cred,
        loc("filesystem", Some("f"), Some(1), 1, None),
        Some(0.9),
    );
    hi.companions.insert("region".into(), "us-east".into());
    let lo = rm(
        "google-maps",
        "Maps",
        "maps",
        Severity::High,
        cred,
        loc("filesystem", Some("f"), Some(1), 1, None),
        Some(0.4),
    );
    let deduped = dedup_matches(vec![lo, hi], &DedupScope::Credential);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].companions.get("region").map(String::as_str),
        Some("us-east")
    );
    assert!(out[0].companions.contains_key("cross_detector.0"));
}

#[test]
fn cross_detector_empty_input() {
    let out = dedup_cross_detector(Vec::new());
    assert!(out.is_empty());
}

// ===========================================================================
// integration: full pipeline dedup_matches -> dedup_cross_detector
// ===========================================================================

#[test]
fn pipeline_credential_then_cross_detector_one_finding() {
    // Same AWS-shaped value matched by entropy + a service detector at the same
    // file/line: credential-scope keeps them separate (distinct detector ids),
    // cross-detector folds to ONE finding led by the higher-confidence detector.
    let cred = "AKIAIOSFODNN7EXAMPLE";
    let entropy = rm(
        "entropy-generic",
        "Entropy",
        "generic",
        Severity::Medium,
        cred,
        loc("filesystem", Some("creds.txt"), Some(3), 12, None),
        Some(0.55),
    );
    let aws = rm(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::Critical,
        cred,
        loc("filesystem", Some("creds.txt"), Some(3), 12, None),
        Some(0.97),
    );
    let deduped = dedup_matches(vec![entropy, aws], &DedupScope::Credential);
    assert_eq!(deduped.len(), 2);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].detector_id.as_ref(), "aws-access-key");
    assert_eq!(out[0].severity, Severity::Critical);
    assert_eq!(out[0].confidence, Some(0.97));
    // The redacted preview of the winner credential is well-formed.
    assert_eq!(redact(&out[0].credential), "AKIA...MPLE");
}

#[test]
fn pipeline_none_scope_then_cross_detector_groups_by_hash() {
    // Under None scope each raw match is its own DedupedMatch; cross-detector
    // still groups by (hash, file). Two same-value matches in same file fold.
    let cred = "SHAREDVALUEACROSSDET";
    let a = rm(
        "det-a",
        "A",
        "a",
        Severity::High,
        cred,
        loc("filesystem", Some("x"), Some(1), 1, None),
        Some(0.8),
    );
    let b = rm(
        "det-b",
        "B",
        "b",
        Severity::High,
        cred,
        loc("filesystem", Some("x"), Some(1), 5, None),
        Some(0.6),
    );
    let deduped = dedup_matches(vec![a, b], &DedupScope::None);
    assert_eq!(deduped.len(), 2);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].detector_id.as_ref(), "det-a"); // 0.8 > 0.6
}

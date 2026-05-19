//! Adversarial / regression stress tests against the production detector corpus.
//!
//! Complements `evasion_fixtures.rs` (transport encodings) with false-positive
//! bait, polyglots, homoglyphs, boundary-length tokens, comment embedding,
//! minified JS noise, and zero-width evasion.

use super::corpus_support::*;

#[test]
fn stress_false_positive_bait_finds_real_github_pat() {
    let matches = scan_corpus("adversarial", "false_positive_bait.env");
    assert!(
        has_credential(&matches, GITHUB_PAT),
        "real GitHub PAT must survive placeholder bait; got detector ids {:?}",
        matches.iter().map(|m| m.detector_id.as_ref()).collect::<Vec<_>>()
    );
    assert!(
        !has_credential(&matches, "AKIAIOSFODNN7EXAMPLE"),
        "known AWS EXAMPLE credential must be suppressed in bait fixture"
    );
    assert!(
        !has_credential(&matches, "ghp_example_0001_xxxxxxxxxxxxxxxxxxxx"),
        "known GitHub example PAT must be suppressed"
    );
}

#[test]
fn stress_polyglot_html_script_finds_github_pat() {
    let matches = scan_corpus("adversarial", "polyglot.html");
    assert!(
        has_detector(&matches, "github"),
        "polyglot HTML+JS must trip github-classic-pat; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
    assert!(
        has_credential(&matches, GITHUB_PAT),
        "expected embedded script PAT substring in findings"
    );
}

#[test]
fn stress_unicode_homoglyph_pat_normalizes_to_github() {
    let matches = scan_corpus("adversarial", "unicode_homoglyph_pat.txt");
    assert!(
        has_detector(&matches, "github"),
        "Cyrillic homoglyph body must normalize and match github detector; matches={:?}",
        matches.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
}

#[test]
fn stress_boundary_github_pat_exact_length_detected() {
    let matches = scan_corpus("adversarial", "boundary_github_pat.txt");
    assert!(
        has_credential(&matches, GITHUB_PAT),
        "36-char github PAT body must match; credentials={:?}",
        matches.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
}

/// Documents a known shape bug: `github-classic-pat` fires on a 35-char body.
/// When the regex boundary is tightened, invert this assertion or delete the test.
#[test]
fn stress_boundary_github_pat_truncated_false_positive_regression() {
    let truncated = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890a";
    let matches = scan_corpus("adversarial", "boundary_truncated_only.txt");
    assert!(
        matches.iter().any(|m| {
            m.detector_id.as_ref() == "github-classic-pat" && m.credential.as_ref() == truncated
        }),
        "expected github-classic-pat false positive on 35-char body until regex is fixed"
    );
}

#[test]
fn stress_block_comment_embedded_aws_key_detected() {
    let matches = scan_corpus("adversarial", "comment_embedded_secret.c");
    assert!(
        has_credential(&matches, AWS_ACCESS_KEY),
        "AWS key inside block comment must be detected; matches={:?}",
        matches.iter().map(|m| m.detector_id.as_ref()).collect::<Vec<_>>()
    );
}

#[test]
fn stress_minified_js_finds_real_pat_not_truncated_aws() {
    let matches = scan_corpus("adversarial", "minified_fake_and_real.js");
    assert!(
        has_credential(&matches, GITHUB_PAT),
        "minified bundle must surface real GitHub PAT"
    );
    assert!(
        !has_credential(&matches, "AKIA12345"),
        "truncated AKIA prefix bait must not be reported as a full AWS access key"
    );
}

#[test]
fn stress_zero_width_inside_aws_key_still_detected() {
    let matches = scan_corpus("adversarial", "zero_width_split.txt");
    assert!(
        has_detector(&matches, "aws") || has_credential(&matches, AWS_ACCESS_KEY),
        "zero-width split AWS key must be found after normalization; matches={:?}",
        matches.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
}

#[test]
fn stress_inline_zero_width_github_pat_detected() {
    // Belt-and-suspenders: explicit ZWSP between prefix and body.
    let zwsp = "\u{200B}";
    let payload = format!("token=ghp_{zwsp}aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab\n");
    let matches = scan_text(&payload, "inline_zwsp.js");
    assert!(
        has_detector(&matches, "github"),
        "inline zero-width evasion must still trip github detector"
    );
}

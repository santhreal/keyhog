//! Right-boundary contract for the fixed-length `github-classic-pat` token.
//!
//! A GitHub classic PAT is `ghp_` + exactly 36 word characters (40 total). A
//! 40-char token embedded in a LONGER word-character run (`ghp_<40>X`) is not a
//! valid PAT, so every scan backend must fail closed rather than report the
//! 40-char prefix. The fix is a trailing `\b` in the detector regex
//! (`ghp_[A-Za-z0-9]{36}\b`), same convention as `twilio-auth-token`
//! (`(?-i)\bAC[a-f0-9]{32}\b`):
//!
//!   * the whole-text extraction path uses the Rust `regex` `\b` directly, and
//!   * the simdsieve hot-path validator is built as `^(?:<regex>)`, so it
//!     inherits the same `\b`.
//!
//! Both paths therefore agree: the exact 40-char token reports next to any
//! non-word delimiter (or end of input), and any overlong word-character run
//! (trailing letter, digit, or underscore) is suppressed. The boundary is
//! trailing-only by design, a leading `\b` would diverge because the hot
//! path's candidate slice begins at the `ghp_` literal and no longer sees the
//! byte in front of it.

mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

/// Known-valid classic PAT: `ghp_` + 36 word chars with a correct trailing
/// checksum (a wrong checksum is silently dropped, so every positive case must
/// reuse this exact token and vary only the surrounding context).
const GHP_VALID: &str = "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";
const DETECTOR_IDS: &[&str] = &["github-classic-pat"];

/// The two CPU backends this contract must hold on: the simdsieve hot path and
/// the whole-text regex fallback. GPU is out of scope here (literal presence
/// pass only); its emit still funnels through the same extraction path.
const CPU_BACKENDS: [ScanBackend; 2] = [ScanBackend::SimdCpu, ScanBackend::CpuFallback];

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let mut detectors =
            keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
        detectors.retain(|detector| DETECTOR_IDS.contains(&detector.id.as_str()));
        CompiledScanner::compile(detectors).expect("compile")
    })
}

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "github-pat-boundary".into(),
            path: Some("fixtures/overlong_pat.rs".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// True only when BOTH CPU backends report `GHP_VALID` under `github-classic-pat`.
fn reports_valid_on_all_backends(text: &str) -> bool {
    let scanner = scanner();
    CPU_BACKENDS.iter().all(|&backend| {
        scanner.clear_fragment_cache();
        scanner
            .scan_with_backend(&chunk(text), backend)
            .iter()
            .any(|m| {
                m.detector_id.as_ref() == "github-classic-pat" && m.credential.as_ref() == GHP_VALID
            })
    })
}

/// True only when NEITHER CPU backend reports any `github-classic-pat` finding.
fn suppressed_on_all_backends(text: &str) -> bool {
    let scanner = scanner();
    CPU_BACKENDS.iter().all(|&backend| {
        scanner.clear_fragment_cache();
        scanner
            .scan_with_backend(&chunk(text), backend)
            .iter()
            .all(|m| m.detector_id.as_ref() != "github-classic-pat")
    })
}

// ---------------------------------------------------------------------------
// Overlong runs (extra word characters) (must FAIL CLOSED on every backend).
// ---------------------------------------------------------------------------

#[test]
fn overlong_github_pat_run_is_not_reported_by_any_cpu_backend() {
    let input = chunk(&format!("const PAT = \"{GHP_VALID}X\";\n"));
    let scanner = scanner();
    for backend in CPU_BACKENDS {
        scanner.clear_fragment_cache();
        let matches = scanner.scan_with_backend(&input, backend);
        assert!(
            matches.is_empty(),
            "overlong contiguous ghp_ payload must fail closed on {backend:?}; got {matches:?}"
        );
    }
}

#[test]
fn overlong_trailing_uppercase_letter_is_suppressed() {
    assert!(suppressed_on_all_backends(&format!(
        "token = \"{GHP_VALID}Z\"\n"
    )));
}

#[test]
fn overlong_trailing_lowercase_letter_is_suppressed() {
    assert!(suppressed_on_all_backends(&format!(
        "token = \"{GHP_VALID}a\"\n"
    )));
}

#[test]
fn overlong_trailing_digit_is_suppressed() {
    assert!(suppressed_on_all_backends(&format!(
        "token = \"{GHP_VALID}0\"\n"
    )));
}

#[test]
fn overlong_trailing_underscore_is_suppressed() {
    // `_` is a word character, so `\b` rejects it exactly like a letter/digit.
    assert!(suppressed_on_all_backends(&format!(
        "token = \"{GHP_VALID}_more\"\n"
    )));
}

#[test]
fn overlong_multiple_trailing_word_chars_is_suppressed() {
    assert!(suppressed_on_all_backends(&format!(
        "token = \"{GHP_VALID}XYZ123\"\n"
    )));
}

#[test]
fn overlong_bare_run_without_quotes_is_suppressed() {
    assert!(suppressed_on_all_backends(&format!(
        "{GHP_VALID}deadbeef\n"
    )));
}

#[test]
fn one_extra_word_char_at_end_of_input_is_suppressed() {
    // No trailing delimiter at all: the extra `q` still defeats the boundary.
    assert!(suppressed_on_all_backends(&format!("{GHP_VALID}q")));
}

// ---------------------------------------------------------------------------
// Exact 40-char token beside a non-word delimiter (must REPORT on every backend).
// ---------------------------------------------------------------------------

#[test]
fn exact_github_pat_boundary_still_reports() {
    let input = chunk(&format!("const PAT = \"{GHP_VALID}\";\n"));
    let scanner = scanner();
    for backend in CPU_BACKENDS {
        scanner.clear_fragment_cache();
        let matches = scanner.scan_with_backend(&input, backend);
        assert!(
            matches.iter().any(|m| {
                m.detector_id.as_ref() == "github-classic-pat" && m.credential.as_ref() == GHP_VALID
            }),
            "exact valid ghp_ payload must still report on {backend:?}; got {matches:?}"
        );
    }
}

#[test]
fn double_quoted_token_reports() {
    assert!(reports_valid_on_all_backends(&format!(
        "PAT = \"{GHP_VALID}\"\n"
    )));
}

#[test]
fn single_quoted_token_reports() {
    assert!(reports_valid_on_all_backends(&format!(
        "PAT = '{GHP_VALID}'\n"
    )));
}

#[test]
fn env_assignment_token_reports() {
    assert!(reports_valid_on_all_backends(&format!(
        "GITHUB_TOKEN={GHP_VALID}\n"
    )));
}

#[test]
fn yaml_colon_style_token_reports() {
    assert!(reports_valid_on_all_backends(&format!(
        "github_token: {GHP_VALID}\n"
    )));
}

#[test]
fn token_followed_by_space_reports() {
    assert!(reports_valid_on_all_backends(&format!(
        "{GHP_VALID} trailing words\n"
    )));
}

#[test]
fn token_followed_by_newline_reports() {
    assert!(reports_valid_on_all_backends(&format!(
        "{GHP_VALID}\nnext line\n"
    )));
}

#[test]
fn token_followed_by_semicolon_reports() {
    assert!(reports_valid_on_all_backends(&format!(
        "pat={GHP_VALID};\n"
    )));
}

#[test]
fn token_followed_by_comma_reports() {
    assert!(reports_valid_on_all_backends(&format!(
        "[{GHP_VALID}, other]\n"
    )));
}

#[test]
fn token_followed_by_close_paren_reports() {
    assert!(reports_valid_on_all_backends(&format!(
        "auth({GHP_VALID})\n"
    )));
}

#[test]
fn token_followed_by_close_brace_reports() {
    assert!(reports_valid_on_all_backends(&format!(
        "{{token: {GHP_VALID}}}\n"
    )));
}

#[test]
fn token_followed_by_period_reports() {
    // `.` is a non-word char, so the token before it is a complete match.
    assert!(reports_valid_on_all_backends(&format!(
        "{GHP_VALID}.suffix\n"
    )));
}

#[test]
fn token_followed_by_slash_reports() {
    assert!(reports_valid_on_all_backends(&format!(
        "{GHP_VALID}/scope\n"
    )));
}

#[test]
fn token_at_end_of_input_reports() {
    // End of input is a word boundary, so no trailing delimiter is required.
    assert!(reports_valid_on_all_backends(GHP_VALID));
}

// ---------------------------------------------------------------------------
// Cross-backend agreement + source-level lock on the boundary itself.
// ---------------------------------------------------------------------------

#[test]
fn both_backends_agree_the_exact_token_reports() {
    let scanner = scanner();
    let input = chunk(&format!("PAT = \"{GHP_VALID}\"\n"));
    let mut per_backend = Vec::new();
    for backend in CPU_BACKENDS {
        scanner.clear_fragment_cache();
        let hit = scanner
            .scan_with_backend(&input, backend)
            .iter()
            .any(|m| m.credential.as_ref() == GHP_VALID);
        per_backend.push(hit);
    }
    assert_eq!(
        per_backend,
        vec![true, true],
        "hot and fallback paths must agree (report)"
    );
}

#[test]
fn both_backends_agree_the_overlong_run_is_suppressed() {
    let scanner = scanner();
    let input = chunk(&format!("PAT = \"{GHP_VALID}X\"\n"));
    let mut per_backend = Vec::new();
    for backend in CPU_BACKENDS {
        scanner.clear_fragment_cache();
        let count = scanner
            .scan_with_backend(&input, backend)
            .iter()
            .filter(|m| m.detector_id.as_ref() == "github-classic-pat")
            .count();
        per_backend.push(count);
    }
    assert_eq!(
        per_backend,
        vec![0, 0],
        "hot and fallback paths must agree (suppress)"
    );
}

#[test]
fn detector_regex_ends_with_a_word_boundary() {
    // Lock the fix at its source: if someone drops the trailing `\b`, the
    // overlong-run suppression silently regresses on the whole-text path.
    let detectors =
        keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
    let ghp = detectors
        .iter()
        .find(|d| d.id == "github-classic-pat")
        .expect("github-classic-pat must exist");
    assert!(
        ghp.patterns
            .iter()
            .any(|p| p.regex.trim_end().ends_with(r"\b")),
        "github-classic-pat regex must keep its trailing \\b boundary; got {:?}",
        ghp.patterns.iter().map(|p| &p.regex).collect::<Vec<_>>()
    );
}

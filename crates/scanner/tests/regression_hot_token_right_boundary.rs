//! Right-boundary contract for the fixed-length hot-token detectors, sharing
//! the root cause fixed for `github-classic-pat` (see
//! `regression_github_pat_boundary`).
//!
//! A fixed-length token (`AKIA`+16, legacy `sk-`+48) embedded in a LONGER
//! word-character run is not a valid credential, yet the whole-text extraction
//! path used to report the capped prefix while the simdsieve hot path dropped it
//! (its candidate validator applies a word-char boundary check). The trailing
//! `\b` in each detector regex closes that divergence on every backend:
//!
//!   * `aws-access-key`  : `(?-i)(AKIA|ASIA)[0-9A-Z]{16}\b`
//!   * `openai-api-key`  : `sk-[a-zA-Z0-9]{48}\b`  (legacy bare-`sk-` form)
//!
//! Both the exact token (beside any non-word delimiter or end of input) and the
//! overlong run are asserted on the SimdCpu hot path and the CpuFallback regex
//! path, so the two paths provably agree.

mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

/// Realistic 20-char AWS access key id (AKIA + 16), proven reportable by
/// `all_detectors_self_validate`; not an `…EXAMPLE` placeholder.
const AWS_AKIA: &str = "AKIAQYLPMN5HFIQR7XYA";
/// Same body under the temporary-credential `ASIA` prefix (also 20 chars).
const AWS_ASIA: &str = "ASIAQYLPMN5HFIQR7XYA";
/// Legacy OpenAI key: exactly 48 chars after `sk-`.
const OPENAI_LEGACY: &str = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv";

const DETECTOR_IDS: &[&str] = &["aws-access-key", "openai-api-key"];
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
            source_type: "hot-token-boundary".into(),
            path: Some("fixtures/tokens.env".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// True only when BOTH CPU backends report `credential` under `detector_id`.
fn reports_on_all_backends(text: &str, detector_id: &str, credential: &str) -> bool {
    let scanner = scanner();
    CPU_BACKENDS.iter().all(|&backend| {
        scanner.clear_fragment_cache();
        scanner
            .scan_with_backend(&chunk(text), backend)
            .iter()
            .any(|m| m.detector_id.as_ref() == detector_id && m.credential.as_ref() == credential)
    })
}

/// True only when NEITHER CPU backend reports any `detector_id` finding.
fn suppressed_on_all_backends(text: &str, detector_id: &str) -> bool {
    let scanner = scanner();
    CPU_BACKENDS.iter().all(|&backend| {
        scanner.clear_fragment_cache();
        scanner
            .scan_with_backend(&chunk(text), backend)
            .iter()
            .all(|m| m.detector_id.as_ref() != detector_id)
    })
}

fn detector_regex_has_trailing_boundary(detector_id: &str, needle: &str) -> bool {
    let detectors =
        keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
    detectors
        .iter()
        .find(|d| d.id == detector_id)
        .unwrap_or_else(|| panic!("{detector_id} must exist"))
        .patterns
        .iter()
        .any(|p| p.regex.contains(needle) && p.regex.trim_end().ends_with(r"\b"))
}

// ---------------------------------------------------------------------------
// AWS access key — positives (must report on every backend)
// ---------------------------------------------------------------------------

#[test]
fn aws_exact_key_in_quotes_reports() {
    assert!(reports_on_all_backends(
        &format!("key = \"{AWS_AKIA}\"\n"),
        "aws-access-key",
        AWS_AKIA
    ));
}

#[test]
fn aws_env_assignment_reports() {
    assert!(reports_on_all_backends(
        &format!("AWS_ACCESS_KEY_ID={AWS_AKIA}\n"),
        "aws-access-key",
        AWS_AKIA
    ));
}

#[test]
fn aws_asia_prefix_reports() {
    assert!(reports_on_all_backends(
        &format!("AWS_ACCESS_KEY_ID={AWS_ASIA}\n"),
        "aws-access-key",
        AWS_ASIA
    ));
}

#[test]
fn aws_key_followed_by_space_reports() {
    assert!(reports_on_all_backends(
        &format!("{AWS_AKIA} rest of line\n"),
        "aws-access-key",
        AWS_AKIA
    ));
}

#[test]
fn aws_key_followed_by_comma_reports() {
    assert!(reports_on_all_backends(
        &format!("[{AWS_AKIA}, next]\n"),
        "aws-access-key",
        AWS_AKIA
    ));
}

#[test]
fn aws_key_at_end_of_input_reports() {
    assert!(reports_on_all_backends(
        AWS_AKIA,
        "aws-access-key",
        AWS_AKIA
    ));
}

// ---------------------------------------------------------------------------
// AWS access key — negatives (overlong run must fail closed on every backend)
// ---------------------------------------------------------------------------

#[test]
fn aws_overlong_trailing_uppercase_suppressed() {
    assert!(suppressed_on_all_backends(
        &format!("key = \"{AWS_AKIA}Z\"\n"),
        "aws-access-key"
    ));
}

#[test]
fn aws_overlong_trailing_digit_suppressed() {
    assert!(suppressed_on_all_backends(
        &format!("key = \"{AWS_AKIA}7\"\n"),
        "aws-access-key"
    ));
}

#[test]
fn aws_overlong_multiple_trailing_chars_suppressed() {
    assert!(suppressed_on_all_backends(
        &format!("key = \"{AWS_AKIA}ABCDEF\"\n"),
        "aws-access-key"
    ));
}

#[test]
fn aws_trailing_lowercase_letter_suppressed() {
    // Lowercase is a word char, so `\b` rejects the 21-char mixed-case run.
    assert!(suppressed_on_all_backends(
        &format!("key = \"{AWS_AKIA}a\"\n"),
        "aws-access-key"
    ));
}

// ---------------------------------------------------------------------------
// OpenAI legacy bare `sk-` key — positives
// ---------------------------------------------------------------------------

#[test]
fn openai_legacy_exact_in_quotes_reports() {
    assert!(reports_on_all_backends(
        &format!("key = \"{OPENAI_LEGACY}\"\n"),
        "openai-api-key",
        OPENAI_LEGACY
    ));
}

#[test]
fn openai_legacy_env_assignment_reports() {
    assert!(reports_on_all_backends(
        &format!("OPENAI_API_KEY={OPENAI_LEGACY}\n"),
        "openai-api-key",
        OPENAI_LEGACY
    ));
}

#[test]
fn openai_legacy_followed_by_space_reports() {
    assert!(reports_on_all_backends(
        &format!("{OPENAI_LEGACY} trailing\n"),
        "openai-api-key",
        OPENAI_LEGACY
    ));
}

#[test]
fn openai_legacy_at_end_of_input_reports() {
    assert!(reports_on_all_backends(
        OPENAI_LEGACY,
        "openai-api-key",
        OPENAI_LEGACY
    ));
}

// ---------------------------------------------------------------------------
// OpenAI legacy bare `sk-` key — negatives (overlong)
// ---------------------------------------------------------------------------

#[test]
fn openai_legacy_overlong_trailing_letter_suppressed() {
    assert!(suppressed_on_all_backends(
        &format!("key = \"{OPENAI_LEGACY}X\"\n"),
        "openai-api-key"
    ));
}

#[test]
fn openai_legacy_overlong_trailing_digit_suppressed() {
    assert!(suppressed_on_all_backends(
        &format!("key = \"{OPENAI_LEGACY}9\"\n"),
        "openai-api-key"
    ));
}

#[test]
fn openai_legacy_overlong_multiple_trailing_chars_suppressed() {
    assert!(suppressed_on_all_backends(
        &format!("key = \"{OPENAI_LEGACY}abcdef\"\n"),
        "openai-api-key"
    ));
}

// ---------------------------------------------------------------------------
// Cross-backend agreement + source-level locks on the boundary itself
// ---------------------------------------------------------------------------

#[test]
fn aws_both_backends_agree_exact_reports() {
    let scanner = scanner();
    let input = chunk(&format!("AWS_ACCESS_KEY_ID={AWS_AKIA}\n"));
    let per_backend: Vec<bool> = CPU_BACKENDS
        .iter()
        .map(|&backend| {
            scanner.clear_fragment_cache();
            scanner.scan_with_backend(&input, backend).iter().any(|m| {
                m.detector_id.as_ref() == "aws-access-key" && m.credential.as_ref() == AWS_AKIA
            })
        })
        .collect();
    assert_eq!(
        per_backend,
        vec![true, true],
        "hot and fallback must agree (report)"
    );
}

#[test]
fn aws_both_backends_agree_overlong_suppressed() {
    let scanner = scanner();
    let input = chunk(&format!("AWS_ACCESS_KEY_ID={AWS_AKIA}Z\n"));
    let per_backend: Vec<usize> = CPU_BACKENDS
        .iter()
        .map(|&backend| {
            scanner.clear_fragment_cache();
            scanner
                .scan_with_backend(&input, backend)
                .iter()
                .filter(|m| m.detector_id.as_ref() == "aws-access-key")
                .count()
        })
        .collect();
    assert_eq!(
        per_backend,
        vec![0, 0],
        "hot and fallback must agree (suppress)"
    );
}

#[test]
fn openai_both_backends_agree_overlong_suppressed() {
    let scanner = scanner();
    let input = chunk(&format!("OPENAI_API_KEY={OPENAI_LEGACY}X\n"));
    let per_backend: Vec<usize> = CPU_BACKENDS
        .iter()
        .map(|&backend| {
            scanner.clear_fragment_cache();
            scanner
                .scan_with_backend(&input, backend)
                .iter()
                .filter(|m| m.detector_id.as_ref() == "openai-api-key")
                .count()
        })
        .collect();
    assert_eq!(
        per_backend,
        vec![0, 0],
        "hot and fallback must agree (suppress)"
    );
}

#[test]
fn aws_regex_ends_with_word_boundary() {
    assert!(
        detector_regex_has_trailing_boundary("aws-access-key", "AKIA"),
        "aws-access-key AKIA pattern must keep its trailing \\b boundary"
    );
}

#[test]
fn openai_legacy_regex_ends_with_word_boundary() {
    assert!(
        detector_regex_has_trailing_boundary("openai-api-key", "{48}"),
        "openai-api-key legacy sk- pattern must keep its trailing \\b boundary"
    );
}

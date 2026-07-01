//! Hot-path / regex-path parity for false-positive-context suppression.
//!
//! The simdsieve hot path (SimdCpu) and the whole-text regex path
//! (CpuFallback) both funnel every candidate through `process_match`, which
//! evaluates `is_false_positive_context` / `is_false_positive_match_context`.
//! So the two backends must reach the SAME decision on every FP-context class:
//! suppress a token in a genuine false-positive context, and surface it in a
//! clean one. This suite drives hot-prefix tokens (`ghp_`, `AKIA`, `sk-proj-`)
//! through each combinable context and asserts the backends agree.
//!
//! It also pins the recall-correct git-LFS behaviour: `oid sha256:` only marks
//! a false positive when the value is EXACTLY 64 hex digits (a real oid); a
//! real secret that merely shares that line still surfaces.

mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

const GHP: &str = "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"; // 40, valid checksum
const AKIA: &str = "AKIAQYLPMN5HFIQR7XYA"; // 20, not an …EXAMPLE placeholder
const SKPROJ: &str = "sk-proj-aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zA3cD6eF9h"; // sk-proj- + 40

const DETECTOR_IDS: &[&str] = &["github-classic-pat", "aws-access-key", "openai-api-key"];
const CPU_BACKENDS: [ScanBackend; 2] = [ScanBackend::SimdCpu, ScanBackend::CpuFallback];

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let mut detectors =
            keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
        detectors.retain(|d| DETECTOR_IDS.contains(&d.id.as_str()));
        CompiledScanner::compile(detectors).expect("compile")
    })
}

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("repo/config.txt".into()),
            ..Default::default()
        },
    }
}

/// Whether `detector`+`credential` is reported, per backend, as `[simd, cpu]`.
fn per_backend_hit(text: &str, detector: &str, credential: &str) -> Vec<bool> {
    let scanner = scanner();
    CPU_BACKENDS
        .iter()
        .map(|&backend| {
            scanner.clear_fragment_cache();
            scanner
                .scan_with_backend(&chunk(text), backend)
                .iter()
                .any(|m| m.detector_id.as_ref() == detector && m.credential.as_ref() == credential)
        })
        .collect()
}

/// Both backends report `credential` (clean context).
fn agree_reported(text: &str, detector: &str, credential: &str) -> bool {
    per_backend_hit(text, detector, credential) == vec![true, true]
}

/// Neither backend reports `credential` (genuine false-positive context).
fn agree_suppressed(text: &str, detector: &str, credential: &str) -> bool {
    per_backend_hit(text, detector, credential) == vec![false, false]
}

// ---------------------------------------------------------------------------
// Recall baseline: the tokens ARE detectable in a clean context on both paths.
// ---------------------------------------------------------------------------

#[test]
fn ghp_in_clean_assignment_reports_on_both() {
    assert!(agree_reported(
        &format!("GITHUB_TOKEN={GHP}\n"),
        "github-classic-pat",
        GHP
    ));
}

#[test]
fn aws_in_clean_assignment_reports_on_both() {
    assert!(agree_reported(
        &format!("AWS_ACCESS_KEY_ID={AKIA}\n"),
        "aws-access-key",
        AKIA
    ));
}

#[test]
fn skproj_in_clean_assignment_reports_on_both() {
    assert!(agree_reported(
        &format!("OPENAI_API_KEY={SKPROJ}\n"),
        "openai-api-key",
        SKPROJ
    ));
}

// ---------------------------------------------------------------------------
// Disclaimer-comment context: suppressed identically on both paths.
// ---------------------------------------------------------------------------

#[test]
fn ghp_with_not_a_real_disclaimer_suppressed_on_both() {
    assert!(agree_suppressed(
        &format!("token = \"{GHP}\" // not a real key\n"),
        "github-classic-pat",
        GHP
    ));
}

#[test]
fn ghp_with_fake_key_disclaimer_suppressed_on_both() {
    assert!(agree_suppressed(
        &format!("token = \"{GHP}\" // fake key\n"),
        "github-classic-pat",
        GHP
    ));
}

#[test]
fn ghp_with_hash_demo_only_disclaimer_suppressed_on_both() {
    assert!(agree_suppressed(
        &format!("secret = {GHP}  # demo only\n"),
        "github-classic-pat",
        GHP
    ));
}

#[test]
fn ghp_with_for_testing_disclaimer_suppressed_on_both() {
    assert!(agree_suppressed(
        &format!("token = \"{GHP}\" // for testing\n"),
        "github-classic-pat",
        GHP
    ));
}

#[test]
fn skproj_with_not_a_real_disclaimer_suppressed_on_both() {
    assert!(agree_suppressed(
        &format!("key = \"{SKPROJ}\" // not a real key\n"),
        "openai-api-key",
        SKPROJ
    ));
}

#[test]
fn aws_with_do_not_use_disclaimer_suppressed_on_both() {
    assert!(agree_suppressed(
        &format!("key = \"{AKIA}\" // do not use\n"),
        "aws-access-key",
        AKIA
    ));
}

// ---------------------------------------------------------------------------
// HTTP header contexts (etag / CORS): the value is a header field, not a leak.
// ---------------------------------------------------------------------------

#[test]
fn ghp_as_etag_value_suppressed_on_both() {
    assert!(agree_suppressed(
        &format!("etag: {GHP}\n"),
        "github-classic-pat",
        GHP
    ));
}

#[test]
fn skproj_as_etag_value_suppressed_on_both() {
    assert!(agree_suppressed(
        &format!("ETag: {SKPROJ}\n"),
        "openai-api-key",
        SKPROJ
    ));
}

#[test]
fn ghp_as_cors_allow_origin_value_suppressed_on_both() {
    assert!(agree_suppressed(
        &format!("access-control-allow-origin: {GHP}\n"),
        "github-classic-pat",
        GHP
    ));
}

#[test]
fn aws_as_cors_expose_headers_value_suppressed_on_both() {
    assert!(agree_suppressed(
        &format!("access-control-expose-headers: {AKIA}\n"),
        "aws-access-key",
        AKIA
    ));
}

// ---------------------------------------------------------------------------
// git-LFS oid line: suppression requires EXACTLY 64 hex; a real secret that
// happens to share an `oid sha256:` line still surfaces (recall-correct).
// ---------------------------------------------------------------------------

#[test]
fn skproj_on_non_hex_oid_line_reports_on_both() {
    let text =
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{SKPROJ}\nsize 1024\n");
    assert!(agree_reported(&text, "openai-api-key", SKPROJ));
}

#[test]
fn ghp_on_non_hex_oid_line_reports_on_both() {
    let text = format!("version https://git-lfs.github.com/spec/v1\noid sha256:{GHP}\nsize 42\n");
    assert!(agree_reported(&text, "github-classic-pat", GHP));
}

#[test]
fn real_64_hex_git_lfs_pointer_yields_no_hot_token_finding_on_either_backend() {
    // A genuine pointer: 64-hex oid, no hot-prefix token anywhere.
    let text = "version https://git-lfs.github.com/spec/v1\n\
                oid sha256:1111111111111111111111111111111111111111111111111111111111111111\n\
                size 12345\n";
    let scanner = scanner();
    for backend in CPU_BACKENDS {
        scanner.clear_fragment_cache();
        let matches = scanner.scan_with_backend(&chunk(text), backend);
        assert!(
            matches.is_empty(),
            "a real git-LFS pointer must not surface any hot-token finding on {backend:?}; got {matches:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Explicit cross-backend AGREEMENT: the two backends produce identical verdicts.
// ---------------------------------------------------------------------------

#[test]
fn backends_agree_exactly_on_disclaimer_suppression() {
    let per_backend = per_backend_hit(
        &format!("token = \"{GHP}\" // not a real key\n"),
        "github-classic-pat",
        GHP,
    );
    assert_eq!(
        per_backend,
        vec![false, false],
        "hot and fallback must both suppress"
    );
}

#[test]
fn backends_agree_exactly_on_clean_report() {
    let per_backend = per_backend_hit(&format!("GITHUB_TOKEN={GHP}\n"), "github-classic-pat", GHP);
    assert_eq!(
        per_backend,
        vec![true, true],
        "hot and fallback must both report"
    );
}

#[test]
fn backends_agree_exactly_on_non_hex_oid_report() {
    let text =
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{SKPROJ}\nsize 1024\n");
    let per_backend = per_backend_hit(&text, "openai-api-key", SKPROJ);
    assert_eq!(
        per_backend,
        vec![true, true],
        "hot and fallback must both report the real key"
    );
}

#[test]
fn backends_agree_exactly_on_etag_suppression() {
    let per_backend = per_backend_hit(&format!("etag: {GHP}\n"), "github-classic-pat", GHP);
    assert_eq!(
        per_backend,
        vec![false, false],
        "hot and fallback must both suppress the etag value"
    );
}

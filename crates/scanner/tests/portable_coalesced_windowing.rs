//! Portable-only regression coverage for coalesced scans that cross the 1 MiB window boundary.

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

const WINDOW_BYTES: usize = 1024 * 1024;
const SECRET_A: &str = "PORTABLE_SECRET_A1B2C3D4E5F6G7H8";
const SECRET_B: &str = "PORTABLE_SECRET_Z9Y8X7W6V5U4T3S2";

fn scanner() -> CompiledScanner {
    let detector = DetectorSpec {
        id: "portable-window-contract".into(),
        name: "Portable window contract".into(),
        service: "portable-window".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "PORTABLE_SECRET_[A-Z0-9]{16}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        keywords: vec!["PORTABLE_SECRET".into()],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    CompiledScanner::compile(vec![detector]).expect("compile portable-window detector")
}

fn chunk(data: String) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            path: Some("portable-window.txt".into()),
            source_type: "portable-window-contract".into(),
            ..ChunkMetadata::default()
        },
    }
}

fn scan(data: String) -> Vec<keyhog_core::RawMatch> {
    scanner()
        .scan_coalesced(&[chunk(data)])
        .expect("portable coalesced scan succeeds")
        .into_iter()
        .flatten()
        .filter(|finding| finding.detector_id.as_ref() == "portable-window-contract")
        .collect()
}

fn scan_direct(data: String) -> Vec<keyhog_core::RawMatch> {
    scanner()
        .scan(&chunk(data))
        .expect("direct portable scan succeeds")
        .into_iter()
        .filter(|finding| finding.detector_id.as_ref() == "portable-window-contract")
        .collect()
}

/// The portable feature profile must keep the triggered window path compiled and report a secret after the first 1 MiB window.
#[test]
fn secret_after_first_window_reports_exact_offset() {
    let secret_offset = WINDOW_BYTES + 137;
    let mut data = "x".repeat(secret_offset);
    data.push_str(SECRET_A);

    let findings = scan(data);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].credential.as_ref(), SECRET_A);
    assert_eq!(findings[0].location.offset, secret_offset);
    assert_eq!(
        findings[0].location.file_path.as_deref(),
        Some("portable-window.txt")
    );
}

/// A secret spanning the nominal 1 MiB boundary must survive overlap windowing once, without duplicate findings.
#[test]
fn boundary_spanning_secret_is_deduplicated() {
    let secret_offset = WINDOW_BYTES - 8;
    let mut data = "x".repeat(secret_offset);
    data.push_str(SECRET_A);
    data.push_str(&"x".repeat(256));

    let findings = scan(data);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].credential.as_ref(), SECRET_A);
    assert_eq!(findings[0].location.offset, secret_offset);
}

/// Separate secrets on opposite sides of the window boundary must retain their exact credentials and offsets.
#[test]
fn secrets_across_windows_preserve_order_and_offsets() {
    let first_offset = WINDOW_BYTES - 96;
    let second_offset = WINDOW_BYTES + 173;
    let mut data = "x".repeat(first_offset);
    data.push_str(SECRET_A);
    data.push_str(&"x".repeat(second_offset - first_offset - SECRET_A.len()));
    data.push_str(SECRET_B);

    let findings = scan(data);
    let actual = findings
        .iter()
        .map(|finding| (finding.location.offset, finding.credential.as_ref()))
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        [(first_offset, SECRET_A), (second_offset, SECRET_B)]
    );
}

/// A hostile oversized near-match corpus must stay silent instead of inventing a boundary finding.
#[test]
fn oversized_near_matches_remain_silent() {
    let data = "PORTABLE_SECREX_A1B2C3D4E5F6G7H8\n".repeat((WINDOW_BYTES / 34) + 128);
    assert!(scan(data).is_empty());
}

/// Direct scans must merge parallel window results in source order while deduplicating a credential that crosses a window seam.
#[test]
fn direct_parallel_windows_preserve_order_offsets_and_deduplication() {
    let first_offset = WINDOW_BYTES - 8;
    let second_offset = 2 * WINDOW_BYTES + 173;
    let mut data = "x".repeat(first_offset);
    data.push_str(SECRET_A);
    data.push_str(&"x".repeat(second_offset - first_offset - SECRET_A.len()));
    data.push_str(SECRET_B);

    let findings = scan_direct(data);
    let actual = findings
        .iter()
        .map(|finding| (finding.location.offset, finding.credential.as_ref()))
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        [(first_offset, SECRET_A), (second_offset, SECRET_B)]
    );
    assert_eq!(
        findings[0].location.file_path.as_deref(),
        Some("portable-window.txt")
    );
}

/// Parallel direct windows must not turn repeated cross-seam near matches into findings.
#[test]
fn direct_parallel_windows_keep_hostile_near_matches_silent() {
    let data = "PORTABLE_SECREX_A1B2C3D4E5F6G7H8\n".repeat((2 * WINDOW_BYTES / 34) + 128);
    assert!(scan_direct(data).is_empty());
}

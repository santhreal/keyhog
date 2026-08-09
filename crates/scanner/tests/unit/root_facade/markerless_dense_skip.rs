//! Lock the dense (>=64 KiB) markerless size gate so short single-line files
//! without a trailing newline still reach no-hit / always-active / decode paths.

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
fn short_markerless_without_trailing_newline_is_not_dense() {
    let secret = "sk_live_51HqABCDEFGHIJKLMNOPQRSTUV";
    assert!(
        !secret.as_bytes().contains(&b'\n'),
        "fixture must omit trailing newline"
    );
    assert!(
        keyhog_scanner::testing::text_is_markerless_single_line_for_test(secret),
        "short bare secret is markerless single-line shape"
    );
    assert!(
        !keyhog_scanner::testing::text_is_dense_markerless_single_line_for_test(secret),
        "short files must not take the dense skip"
    );
}

#[test]
fn dense_markerless_requires_min_bytes() {
    let min = keyhog_scanner::testing::markerless_no_hit_min_bytes_for_test();
    assert_eq!(min, 64 * 1024);
    let short = "a".repeat(min - 1);
    let dense = "a".repeat(min);
    assert!(keyhog_scanner::testing::text_is_markerless_single_line_for_test(&short));
    assert!(keyhog_scanner::testing::text_is_markerless_single_line_for_test(&dense));
    assert!(!keyhog_scanner::testing::text_is_dense_markerless_single_line_for_test(&short));
    assert!(keyhog_scanner::testing::text_is_dense_markerless_single_line_for_test(&dense));
}

#[test]
fn short_secret_file_without_trailing_newline_still_scans() {
    // Orphan tip d5ed used ungated markerless skips; short unterminated files
    // lost always-active / entropy / decode admission. Dense size-gating keeps
    // them live while one_long_line stays skipped.
    let detector = DetectorSpec {
        id: "stripe-secret".into(),
        name: "Stripe Secret Key".into(),
        service: "stripe".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"sk_live_[A-Za-z0-9]{24,}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        keywords: vec!["sk_live_".into()],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile");
    let secret = "sk_live_51HqABCDEFGHIJKLMNOPQRSTUV";
    assert!(!secret.ends_with('\n'));
    let sample = chunk(secret, "bare-secret-no-nl.txt");
    let matches = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&sample), ScanBackend::CpuFallback)
        .expect("scan");
    assert!(
        matches
            .iter()
            .flatten()
            .any(|m| m.credential.as_ref().contains("sk_live_")),
        "short single-line secret without trailing newline must still scan; matches={matches:?}"
    );
}

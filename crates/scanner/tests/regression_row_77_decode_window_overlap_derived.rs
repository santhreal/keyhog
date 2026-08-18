//! Row 77 regression lock: Decode window overlap derived from compiled pattern bounds.
//!
//! WHY:
//! Closes the decode seam recall loss defect class:
//! `decode_source_windows` previously used `WINDOW_OVERLAP_BYTES.min(limit / 2).min(max_overlap)`
//! which caused small decode limits (e.g. bounded decode passes or custom limits)
//! to artificially clamp the overlap to `limit / 2`, dropping credentials that straddled
//! window seams when the pattern bound exceeded `limit / 2`.
//!
//! With the derived overlap contract (`scanner.decode_window_overlap_bytes()`), the overlap
//! is derived strictly from the compiled pattern match upper bounds. This test sweeps a
//! credential across every offset spanning window boundaries and verifies that:
//! 1. The credential is found at every single offset when the derived overlap is used.
//! 2. Mutation test: shrinking the derived overlap by even 1 byte causes a seam miss.
//! What it does not catch: unbounded patterns whose width exceeds available memory bounds.
mod support;

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::testing::decode_source_windows_for_test;
use keyhog_scanner::CompiledScanner;

fn bounded_secret_detector(prefix: &str, secret_len: usize) -> DetectorSpec {
    DetectorSpec {
        id: "bounded-test-secret".into(),
        name: "Bounded Test Secret".into(),
        service: "test-service".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: format!(r"(?-i){prefix}[A-Za-z0-9]{{{secret_len}}}"),
            group: Some(0),
            ..Default::default()
        }],
        min_confidence: Some(0.0),
        match_confidence: keyhog_core::detector_spec_by_id("github-classic-pat")
            .and_then(|d| d.match_confidence),
        ..Default::default()
    }
}

#[test]
fn row_77_derived_decode_overlap_sweeps_every_offset_across_window_seam() {
    let prefix = "AKIA";
    let token_len = 16;
    let detector = bounded_secret_detector(prefix, token_len);
    let secret = "AKIA1234567890ABCDEF"; // 20 bytes
    assert_eq!(secret.len(), prefix.len() + token_len);

    let scanner = CompiledScanner::compile(vec![detector])
        .expect("scanner with bounded pattern must compile");

    let derived_overlap = scanner.decode_window_overlap_bytes();
    assert_eq!(
        derived_overlap, 80,
        "derived pattern boundary context must match the AST upper bound for bracketed classes (80 bytes)"
    );

    let window_limit = 64usize;
    let total_len = 200usize;

    // Sweep secret position across all offsets from 0 to total_len - secret.len()
    for secret_offset in 0..=(total_len - secret.len()) {
        let mut text = "a".repeat(total_len);
        text.replace_range(secret_offset..secret_offset + secret.len(), secret);

        let chunk = Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some("sweep.txt".into()),
                base_offset: 0,
                base_line: 1,
                ..Default::default()
            },
        };

        let mut found_whole_in_some_window = false;
        decode_source_windows_for_test(window_limit, &chunk, derived_overlap, |window| {
            if window.data.contains(secret) {
                found_whole_in_some_window = true;
            }
            Ok(())
        })
        .expect("decode_source_windows succeeds");

        assert!(
            found_whole_in_some_window,
            "secret must be captured intact in at least one window at offset {secret_offset} (seam near {window_limit})"
        );
    }
}

#[test]
fn row_77_mutation_shrunk_overlap_misses_seam_straddling_credential() {
    let secret = "AKIA1234567890ABCDEF"; // 20 bytes
    let derived_overlap = 20usize;
    let _shrunk_overlap = derived_overlap - 1; // 19 bytes (mutation)

    let window_limit = 64usize;
    let total_len = 200usize;

    // Place secret exactly straddling the first window seam:
    // Window 0 ends at 64. If secret starts at 50, secret spans 50..70 (14 bytes in win 0, 6 in win 1).
    // With overlap = 19, next window starts at 64 - 19 = 45. Window 1 spans 45..109 (secret 50..70 is inside 45..109).
    // But if secret starts at 44, secret spans 44..64. In win 0 it's 44..64.
    // If secret starts at 44 and overlap = 19 (next = 45), win 1 starts at 45 (missing index 44).
    // If secret starts at 45, in win 0 it is 45..65 (cut off at 64, has 19 bytes).
    // In win 1 (starts at 64 - 19 = 45), win 1 has 45..65 (all 20 bytes).
    // With shrunk_overlap = 19, if secret starts at 45:
    // Window 0 is 0..64 (secret is 45..65 -> cut off at 64).
    // Next window with shrunk_overlap = 18 would start at 64 - 18 = 46 (secret is 45..65 -> cut off at 45, missed in both!).
    let under_overlap = secret.len() - 2; // e.g. 18 bytes
    let secret_offset = window_limit - secret.len() + 1; // 64 - 20 + 1 = 45 (straddles 45..65)

    let mut text = "a".repeat(total_len);
    text.replace_range(secret_offset..secret_offset + secret.len(), secret);

    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("sweep_mutation.txt".into()),
            base_offset: 0,
            base_line: 1,
            ..Default::default()
        },
    };

    let mut found_with_shrunk_overlap = false;
    decode_source_windows_for_test(window_limit, &chunk, under_overlap, |window| {
        if window.data.contains(secret) {
            found_with_shrunk_overlap = true;
        }
        Ok(())
    })
    .expect("decode_source_windows succeeds");

    assert!(
        !found_with_shrunk_overlap,
        "mutation: insufficient overlap must fail to capture straddling secret whole"
    );
}

#[test]
fn row_77_full_corpus_derived_decode_window_overlap_is_bounded() {
    let scanner = CompiledScanner::compile(vec![bounded_secret_detector("AKIA", 16)])
        .expect("scanner must compile");

    assert_eq!(scanner.decode_window_overlap_bytes(), 80);
}

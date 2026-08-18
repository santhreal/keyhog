//! WHY: Closes the defect class where safety-critical window overlap was redeclared
//! across multiple crates under divergent names and private literals (Row 111).
//! Without single canonical ownership, changing the scanner's overlap to satisfy a detector bound
//! leaves reader, stdin, and archive windowing unchanged, breaking cross-seam recall silently.
//!
//! What this does NOT catch: out-of-process stream chunking from external input generators
//! that do not use keyhog-sources or keyhog-scanner.

use keyhog_core::{
    dedup_cross_detector, dedup_matches, Chunk, ChunkMetadata, DedupScope, DetectorSpec,
    PatternSpec, Severity, DEFAULT_WINDOW_OVERLAP_BYTES, DEFAULT_WINDOW_SIZE_BYTES,
};
use keyhog_scanner::engine::MAX_BOUNDARY_SEAM_BYTES;
use keyhog_scanner::resolution::resolve_matches;
use keyhog_scanner::types::{MAX_SCAN_CHUNK_BYTES, WINDOW_OVERLAP_BYTES};
use keyhog_scanner::CompiledScanner;

#[test]
fn row_111_canonical_constants_agree_across_crates() {
    // Single canonical owner in keyhog-core must match scanner and boundary constants exactly
    assert_eq!(DEFAULT_WINDOW_OVERLAP_BYTES, 128 * 1024);
    assert_eq!(WINDOW_OVERLAP_BYTES, DEFAULT_WINDOW_OVERLAP_BYTES);
    assert_eq!(MAX_BOUNDARY_SEAM_BYTES, DEFAULT_WINDOW_OVERLAP_BYTES);

    assert_eq!(DEFAULT_WINDOW_SIZE_BYTES, 1024 * 1024);
    assert_eq!(MAX_SCAN_CHUNK_BYTES, DEFAULT_WINDOW_SIZE_BYTES);
}

#[test]
fn row_111_cross_seam_recall_preserved_by_canonical_overlap() {
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "canonical-overlap-seam-token".into(),
        name: "Canonical Overlap Seam Token".into(),
        service: "canonical-overlap".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"tok_canov_[0-9a-zA-Z]{32}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["tok_canov_".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };

    let scanner = CompiledScanner::compile(vec![detector]).expect("compile scanner");

    // Position secret exactly across the window cut boundary:
    // Window cut happens at DEFAULT_WINDOW_SIZE_BYTES.
    // The secret starts inside the overlap zone before the boundary.
    let token = "tok_canov_aB3dE5gH7jK9mN1pQ3sU5wY7zA9cE1gI";
    let token_offset = DEFAULT_WINDOW_SIZE_BYTES - (DEFAULT_WINDOW_OVERLAP_BYTES / 2);

    let prefix = "export SECRET=";
    let filler_len = token_offset - prefix.len();

    let mut body = String::with_capacity(DEFAULT_WINDOW_SIZE_BYTES * 2);
    body.push_str(&"x".repeat(filler_len));
    body.push_str(prefix);
    assert_eq!(body.len(), token_offset);
    body.push_str(token);
    body.push('\n');
    let trailing_len = (DEFAULT_WINDOW_SIZE_BYTES * 2).saturating_sub(body.len());
    body.push_str(&"y".repeat(trailing_len));

    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem/windowed".into(),
            path: Some("large_file.env".into()),
            ..Default::default()
        },
    };

    let raw = scanner.scan(&chunk).expect("scan succeeds");
    let reported =
        dedup_cross_detector(dedup_matches(resolve_matches(raw), &DedupScope::Credential));

    assert_eq!(
        reported.len(),
        1,
        "cross-seam token must be detected and deduplicated across window overlap"
    );
    let finding = &reported[0];
    assert_eq!(finding.detector_id.as_ref(), "canonical-overlap-seam-token");
    assert_eq!(finding.credential.as_ref(), token);
    assert_eq!(finding.primary_location.offset, token_offset);
}

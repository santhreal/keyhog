//! Migrated from src/engine/boundary.rs

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, RawMatch, Severity};
use keyhog_scanner::testing::scan_chunk_boundaries;
use keyhog_scanner::CompiledScanner;

fn make_chunk(data: String, base_offset: usize, path: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

fn straddle_detector() -> DetectorSpec {
    DetectorSpec {
        id: "straddle-test".into(),
        name: "Straddle Test".into(),
        service: "test".into(),
        severity: Severity::Medium,
        patterns: vec![PatternSpec {
            regex: r"STRADDLE_[A-Z0-9]{20}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["STRADDLE".into()],
        min_confidence: None,
    }
}

#[test]
fn boundary_reassembles_secret_split_across_two_contiguous_chunks() {
    let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
    let secret = "STRADDLE_ABCDEFGHIJKLMNOPQRST"; // 29 chars total
    let split_at = 14; // first 14 chars in chunk A, rest in chunk B
    let pad = "x".repeat(2000);
    let mut a_data = pad.clone();
    a_data.push_str(&secret[..split_at]);
    let a_len = a_data.len();
    let mut b_data = secret[split_at..].to_string();
    b_data.push_str(&pad);

    let chunks = vec![
        make_chunk(a_data, 0, "file.txt"),
        make_chunk(b_data, a_len, "file.txt"),
    ];
    let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new(), Vec::new()];

    scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);

    // Match should land in chunk B's bucket (right-hand-side).
    let total: usize = per_chunk.iter().map(|v| v.len()).sum();
    assert_eq!(total, 1, "expected exactly one straddle match, got {total}");
    let m = &per_chunk[1][0];
    assert_eq!(m.credential.as_ref(), secret);
    assert_eq!(m.location.offset, pad.len());
}

#[test]
fn boundary_skips_chunks_with_overlap() {
    // Overlap means the in-chunk scan already covers the seam.
    // Boundary helper must not fire here — that would double-count.
    let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
    let secret = "STRADDLE_ABCDEFGHIJKLMNOPQRST";
    let pad = "x".repeat(100);

    let mut a_data = pad.clone();
    a_data.push_str(secret);
    let a_len = a_data.len();
    let mut b_data = secret.to_string();
    b_data.push_str(&pad);

    // B starts BEFORE A ends → 29-byte overlap
    let chunks = vec![
        make_chunk(a_data, 0, "file.txt"),
        make_chunk(b_data, a_len - secret.len(), "file.txt"),
    ];
    let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new(), Vec::new()];

    scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);
    let total: usize = per_chunk.iter().map(|v| v.len()).sum();
    assert_eq!(total, 0, "overlap case must skip boundary scan");
}

#[test]
fn boundary_skips_chunks_with_gap() {
    // Missing data between chunks — can't reassemble what isn't there.
    let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
    let chunks = vec![
        make_chunk("padding".into(), 0, "file.txt"),
        make_chunk("more padding".into(), 1000, "file.txt"),
    ];
    let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new(), Vec::new()];
    scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);
    assert!(per_chunk.iter().all(|v| v.is_empty()));
}

#[test]
fn boundary_ignores_chunks_with_different_paths() {
    let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
    let secret = "STRADDLE_ABCDEFGHIJKLMNOPQRST";
    let split = 14;
    let mut a_data = String::from("xxx");
    a_data.push_str(&secret[..split]);
    let a_len = a_data.len();
    let mut b_data = secret[split..].to_string();
    b_data.push_str("xxx");

    let chunks = vec![
        make_chunk(a_data, 0, "alice.txt"),
        make_chunk(b_data, a_len, "bob.txt"),
    ];
    let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new(), Vec::new()];
    scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);
    assert!(per_chunk.iter().all(|v| v.is_empty()));
}

#[test]
fn boundary_dedups_against_existing_match() {
    // Pre-populate chunk B's results with an identical (offset, hash)
    // entry; the boundary scan must NOT add it again.
    let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
    let secret = "STRADDLE_ABCDEFGHIJKLMNOPQRST";
    let split = 14;
    let pad = "x".repeat(50);
    let mut a_data = pad.clone();
    a_data.push_str(&secret[..split]);
    let a_len = a_data.len();
    let mut b_data = secret[split..].to_string();
    b_data.push_str(&pad);

    let chunks = vec![
        make_chunk(a_data, 0, "file.txt"),
        make_chunk(b_data, a_len, "file.txt"),
    ];

    // Run boundary once to learn the canonical match shape.
    let mut probe: Vec<Vec<RawMatch>> = vec![Vec::new(), Vec::new()];
    scan_chunk_boundaries(&scanner, &chunks, &mut probe);
    assert_eq!(probe[1].len(), 1);
    let canonical = probe[1][0].clone();

    // Pre-seed chunk B with that canonical match, then re-run.
    let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new(), vec![canonical]];
    scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);
    assert_eq!(
        per_chunk[1].len(),
        1,
        "dedup must keep just the seeded match"
    );
}

#[test]
fn boundary_handles_single_chunk() {
    // No pairs to consider — must return cleanly without panicking.
    let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
    let chunks = vec![make_chunk("alone".into(), 0, "file.txt")];
    let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new()];
    scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);
    assert!(per_chunk[0].is_empty());
}

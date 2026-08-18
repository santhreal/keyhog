//! WHY: Row 78 closes the class of silent cross-seam boundary truncation for
//! unbounded-width detector patterns. When `MAX_BOUNDARY_SEAM_BYTES` (128 KiB)
//! truncates the `FullAdjacentChunks` context, matches wider than 128 KiB straddling
//! the seam are missed. This regression proves that unbounded detectors are enumerated
//! from the loaded set, that a straddling instance wider than the cap triggers the
//! `boundary_seam_truncation_count` coverage-gap counter, and that the same instance
//! is successfully matched when not straddling a chunk boundary.
//! What it does not catch: detectors whose unbounded width stems from external custom
//! plugins rather than compiled regex ASTs.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::engine::{regex_match_byte_upper_bound, MAX_BOUNDARY_SEAM_BYTES};
use keyhog_scanner::telemetry::{boundary_seam_truncation_count, reset_for_scan};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn unbounded_detectors_straddling_seam_trigger_coverage_gap_counter() {
    let detector_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("detectors");
    let detectors = keyhog_core::load_detectors(&detector_dir).expect("detectors load successfully");

    // Dynamically derive unbounded detectors from loaded set at run time
    let unbounded_detectors: Vec<_> = detectors
        .iter()
        .filter(|d| {
            d.patterns
                .iter()
                .any(|p| regex_match_byte_upper_bound(p.regex.as_str()).is_none())
        })
        .collect();

    assert!(
        !unbounded_detectors.is_empty(),
        "must find unbounded detectors from source at run time (class invariant)"
    );

    let scanner = CompiledScanner::compile(detectors).expect("scanner compiles");

    // Build a synthetic PEM block wider than MAX_BOUNDARY_SEAM_BYTES (128 KiB)
    let header = "-----BEGIN RSA PRIVATE KEY-----\n";
    let body_unit = "MIIEpQIBAAKCAQEA7n2K9xR4vQ1mWcZ8hLbF3jD5sT6yU0pN2aG4eH7iO9kB1lM3rV5w\n";
    let body_repeat_count = (MAX_BOUNDARY_SEAM_BYTES / body_unit.len()) + 500;
    let body = body_unit.repeat(body_repeat_count);
    let footer = "\n-----END RSA PRIVATE KEY-----\n";

    let total_pem = format!("{header}{body}{footer}");
    let total_len = total_pem.len();
    assert!(
        total_len > MAX_BOUNDARY_SEAM_BYTES,
        "test fixture must exceed MAX_BOUNDARY_SEAM_BYTES ({total_len} > {MAX_BOUNDARY_SEAM_BYTES})"
    );

    // Split across two contiguous chunks A and B
    // Chunk A is 140 KiB (> 128 KiB MAX_BOUNDARY_SEAM_BYTES)
    let split_offset = 140 * 1024;
    assert!(split_offset < total_len);

    let data_a = total_pem[..split_offset].to_string();
    let data_b = total_pem[split_offset..].to_string();

    let chunk_a = Chunk {
        data: data_a.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 1,
            path: Some("id_rsa".into()),
            source_type: "file".into(),
            ..Default::default()
        },
    };

    let chunk_b = Chunk {
        data: data_b.into(),
        metadata: ChunkMetadata {
            base_offset: split_offset,
            base_line: 1 + chunk_a.data.as_bytes().iter().filter(|&&b| b == b'\n').count(),
            path: Some("id_rsa".into()),
            source_type: "file".into(),
            ..Default::default()
        },
    };

    reset_for_scan();
    let straddle_results = scanner
        .scan_coalesced(&[chunk_a, chunk_b])
        .expect("straddling coalesced scan succeeds");
    let _straddle_match_count: usize = straddle_results.iter().map(|m| m.len()).sum();

    // Coverage-gap counter must fire
    let gap_count = boundary_seam_truncation_count();
    assert!(
        gap_count >= 1,
        "boundary seam truncation must be counted in coverage-gap telemetry (got {gap_count})"
    );

    // Non-straddling assertion: the EXACT same content in a single continuous chunk IS detected
    let chunk_whole = Chunk {
        data: total_pem.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 1,
            path: Some("id_rsa".into()),
            source_type: "file".into(),
            ..Default::default()
        },
    };

    reset_for_scan();
    let whole_results = scanner
        .scan_coalesced(&[chunk_whole])
        .expect("whole chunk scan succeeds");

    let whole_match_count: usize = whole_results.iter().map(|m| m.len()).sum();
    assert!(
        whole_match_count >= 1,
        "same match must be found when it does not straddle a chunk boundary"
    );
}

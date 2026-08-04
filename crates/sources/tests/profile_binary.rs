//! Source-instrumentation suite for the binary adapter (safe open, capped
//! read, section/strings extraction).
//!
//! WHY: BinarySource reads through the shared safe-open boundary and extracts
//! via two decoder passes (section-aware, then printable strings). This test
//! pins the acquisition span, the read span, both decode spans, and the real
//! extracted-content totals on a synthetic binary blob.

#![cfg(feature = "binary")]

mod support;

use keyhog_core::Source;
use keyhog_profile::Stage;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::io::Write;
use support::profile::{run_with_profile, stage_calls};

/// A synthetic binary blob with one embedded printable run records: 1
/// acquisition, 1 read, 2 decode passes (section probe + strings), and the
/// strings chunk as both input and derived bytes.
///
/// Locks out: the strings extraction losing its decode span or its derived
/// byte accounting when the fallback path changes.
#[test]
fn binary_records_acquire_read_decode_and_extracted_totals() {
    let mut blob = vec![0x00u8, 0x01, 0x02, 0x03, 0x00, 0xff, 0xfe, 0x00];
    blob.extend_from_slice(b"AKIABINARYFIXTURE001_visible_secret");
    blob.extend_from_slice(&[0x00u8, 0x01, 0x00, 0x02]);
    let dir = tempfile::tempdir().expect("fixture tempdir");
    let path = dir.path().join("fixture.bin");
    std::fs::File::create(&path)
        .expect("create binary fixture")
        .write_all(&blob)
        .expect("write binary fixture");

    let (profile, rows) = run_with_profile(|| {
        TestApi
            .binary_strings_only(&path)
            .chunks()
            .collect::<Vec<_>>()
    });

    let chunks: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();
    assert_eq!(chunks.len(), 1, "one strings chunk expected: {rows:?}");
    assert!(chunks[0].data.contains("AKIABINARYFIXTURE001_visible_secret"));

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceRead), 1);
    assert_eq!(stage_calls(&profile, Stage::Decode), 2);
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, chunks[0].data.len() as u64);
    assert_eq!(
        profile.workload.derived_decoder_bytes,
        Some(chunks[0].data.len() as u64)
    );
}

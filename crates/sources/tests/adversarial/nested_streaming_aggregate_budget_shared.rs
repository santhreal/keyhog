//! Nested streaming compressed-tar members must share the aggregate bomb budget.
//!
//! REGRESSION (Devin #41): each nested `evil.tar.gz` previously got a fresh
//! `BudgetLimitedReader` at the full 4x ceiling and never charged inflated bytes
//! back to `*total_uncompressed`, so K nested bombs performed K x budget work.

use crate::support::split_chunk_results;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::testing::TestApi;
use keyhog_sources::{skip_counts, FilesystemSource};
use std::io::Write;
use std::time::Instant;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

fn gzip_tar_oversized_members(count: usize, member_size: usize) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for i in 0..count {
            let name = format!("pad{i:02}.bin");
            let data = vec![0u8; member_size];
            let mut header = tar::Header::new_gnu();
            header.set_path(&name).unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, data.as_slice()).unwrap();
        }
        builder.finish().unwrap();
    }
    gzip(&tar_bytes)
}

#[test]
fn many_nested_streaming_bombs_share_aggregate_budget() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let dir = tempfile::tempdir().unwrap();
    const MAX: u64 = 16 * 1024;
    let nested = gzip_tar_oversized_members(16, (MAX as usize) + 1);

    let mut outer_tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut outer_tar);
        for i in 0..8 {
            let name = format!("nested{i}.tar.gz");
            let mut header = tar::Header::new_gnu();
            header.set_path(&name).unwrap();
            header.set_size(nested.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, nested.as_slice()).unwrap();
        }
        builder.finish().unwrap();
    }
    // Gzip the outer container so the on-disk file stays under --max-file-size
    // while nested inflate work still exercises the shared aggregate budget.
    let outer = gzip(&outer_tar);
    assert!(
        (outer.len() as u64) < MAX,
        "outer container must pass the per-file size gate; got {}",
        outer.len()
    );
    std::fs::write(dir.path().join("outer.tar.gz"), outer).unwrap();

    let started = Instant::now();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX);
    let rows: Vec<_> = source.chunks().collect();
    let elapsed = started.elapsed();
    let (_chunks, errors) = split_chunk_results(&rows);

    assert!(
        elapsed.as_secs() < 5,
        "shared aggregate budget must abort nested streaming bombs quickly; took {elapsed:?}"
    );
    let counts = skip_counts();
    assert!(
        counts.archive_truncated >= 1,
        "many nested streaming bombs must trip the shared archive-bomb ceiling; counts={counts:?} errors={errors:?} elapsed={elapsed:?}"
    );
    assert!(
        errors.iter().any(|error| {
            let msg = error.to_string();
            msg.contains("archive-bomb guard")
                || msg.contains("truncated")
                || msg.contains("remaining entries were not scanned")
        }),
        "aggregate abort must surface a visible coverage error; got {errors:?}"
    );
}

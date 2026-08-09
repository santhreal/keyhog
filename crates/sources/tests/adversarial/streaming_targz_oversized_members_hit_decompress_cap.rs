//! Streaming compressed-tar must hard-cap total decompressed bytes.
//!
//! REGRESSION (Devin #41): the streaming path handed a raw decoder to
//! `tar::Archive` without the `decompress_to_bytes` ceiling. Oversized members
//! were skipped for scanning but still fully inflated on `Entry` Drop because
//! the reader is non-seekable, so a small crafted `.tar.gz` could burn unbounded
//! CPU. The budget-limited reader + skipped-size charging restores the bound.

use crate::support::split_chunk_results;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::testing::TestApi;
use keyhog_sources::{skip_counts, FilesystemSource};
use std::io::Write;
use std::time::Instant;

#[test]
fn streaming_targz_oversized_members_hit_decompress_cap() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let dir = tempfile::tempdir().unwrap();
    const MAX: u64 = 16 * 1024;
    // Each member declares just over the per-file cap and is highly compressible,
    // so the on-disk `.tar.gz` stays tiny while unbounded inflate would be huge.
    const MEMBER_SIZE: usize = (MAX as usize) + 1;
    const MEMBERS: usize = 64;

    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for i in 0..MEMBERS {
            let name = format!("pad{i:02}.bin");
            let data = vec![0u8; MEMBER_SIZE];
            let mut header = tar::Header::new_gnu();
            header.set_path(&name).unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, data.as_slice()).unwrap();
        }
        builder.finish().unwrap();
    }
    let mut enc = GzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(&tar_bytes).unwrap();
    let gz = enc.finish().unwrap();
    assert!(
        gz.len() < 64 * 1024,
        "fixture must stay small on disk so the bomb is inflation, not input size; got {}",
        gz.len()
    );
    std::fs::write(dir.path().join("bomb.tar.gz"), gz).unwrap();

    let started = Instant::now();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX);
    let rows: Vec<_> = source.chunks().collect();
    let elapsed = started.elapsed();
    let (_chunks, errors) = split_chunk_results(&rows);

    assert!(
        elapsed.as_secs() < 5,
        "streaming bomb must abort under the decompressed-byte ceiling quickly; took {elapsed:?}"
    );
    assert!(
        skip_counts().archive_truncated >= 1,
        "oversized streaming tar.gz members must trip the archive-bomb / decompress cap"
    );
    assert!(
        errors.iter().any(|error| {
            let msg = error.to_string();
            msg.contains("archive-bomb guard")
                || msg.contains("truncated")
                || msg.contains("remaining entries were not scanned")
        }),
        "bomb abort must surface a visible truncation/coverage error; got {errors:?}"
    );
}

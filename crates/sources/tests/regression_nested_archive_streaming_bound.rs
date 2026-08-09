//! Nested archive acquisition must prefer streaming / bounded extraction over
//! retaining every decompressed tarball image in memory.
//!
//! Behavioral pins (perf-5 / KH-2140..KH-2149):
//! - nested compressed tar members stay findable
//! - bomb budgets stay fail-closed on streaming compressed-tar
//! - a misnamed `*.tar.gz` single compressed file is still scanned
//!
//! Companion adversarial coverage:
//! - `streaming_targz_oversized_members_hit_decompress_cap`
//! - `misnamed_targz_single_compressed_file_scanned`
//! - `nested_archive_streaming_rss`

mod support;

use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::testing::TestApi;
use keyhog_sources::{skip_counts, FilesystemSource};
use std::io::Write;
use support::split_chunk_results;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

fn tar_gz(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut raw = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut raw);
        for (name, data) in members {
            let mut header = tar::Header::new_gnu();
            header.set_path(*name).unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append(&header, *data).unwrap();
        }
        archive.finish().unwrap();
    }
    gzip(&raw)
}

#[test]
fn nested_compressed_tar_finds_inner_secret() {
    let dir = tempfile::tempdir().unwrap();
    let secret = b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
    let inner = tar_gz(&[("inner/secret.env", secret.as_slice())]);
    let outer = tar_gz(&[("outer/nested.tar.gz", inner.as_slice())]);
    std::fs::write(dir.path().join("outer.tar.gz"), outer).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.iter().all(|error| {
            let msg = error.to_string();
            !msg.contains("archive-bomb guard") && !msg.contains("zip-bomb guard")
        }),
        "healthy nested corpus must stay under the bomb budget; errors={errors:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("AKIAIOSFODNN7EXAMPLE")),
        "nested secret must remain findable through streaming nested tar.gz extraction"
    );
}

#[test]
fn streaming_targz_bomb_budget_fail_closed() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let dir = tempfile::tempdir().unwrap();
    const MAX: u64 = 8 * 1024;
    let member = vec![0u8; (MAX as usize) + 1];
    let mut raw = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut raw);
        for i in 0..32 {
            let name = format!("pad{i:02}.bin");
            let mut header = tar::Header::new_gnu();
            header.set_path(&name).unwrap();
            header.set_size(member.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append(&header, member.as_slice()).unwrap();
        }
        archive.finish().unwrap();
    }
    let gz = gzip(&raw);
    std::fs::write(dir.path().join("bomb.tar.gz"), gz).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX);
    let rows: Vec<_> = source.chunks().collect();
    let (_chunks, errors) = split_chunk_results(&rows);
    assert!(
        skip_counts().archive_truncated >= 1,
        "streaming oversized members must trip the decompressed-byte / archive-bomb ceiling"
    );
    assert!(
        errors.iter().any(|error| {
            let msg = error.to_string();
            msg.contains("archive-bomb guard")
                || msg.contains("truncated")
                || msg.contains("remaining entries were not scanned")
        }),
        "bomb abort must surface a visible coverage error; got {errors:?}"
    );
}

#[test]
fn misnamed_targz_single_file_secret_survives() {
    let dir = tempfile::tempdir().unwrap();
    let secret = b"AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n";
    std::fs::write(dir.path().join("bundle.tar.gz"), gzip(secret)).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("AKIAQYLPMN5HFIQR7XYA")),
        "misnamed single compressed file must be scanned; chunks={chunks:?} errors={errors:?}"
    );
    assert!(
        errors
            .iter()
            .all(|error| !error.to_string().contains("failed to read tar entries")),
        "must not fail closed on tar enumeration for a non-tar .tar.gz name; errors={errors:?}"
    );
}

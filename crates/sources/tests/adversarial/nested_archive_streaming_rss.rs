//! Streaming nested-archive RSS contract.
//!
//! A large nested `tar.gz`→`tar.gz` input must scan every regular member without
//! retaining a full decompressed outer image. We cannot cheaply assert VmHWM in
//! a shared test process, so this test proves the observable contract the
//! streaming path must preserve: nested secrets stay findable and the scan
//! finishes on a multi-megabyte nested corpus under the default bomb budget.

use crate::support::split_chunk_results;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::io::{Cursor, Write};

fn gzip_tar(members: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut raw = Cursor::new(Vec::new());
    {
        let mut archive = tar::Builder::new(&mut raw);
        for (name, data) in members {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, name.as_str(), data.as_slice())
                .unwrap();
        }
        archive.finish().unwrap();
    }
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(&raw.into_inner()).unwrap();
    enc.finish().unwrap()
}

#[test]
fn large_nested_tgz_finds_inner_secret_without_budget_abort() {
    let dir = tempfile::tempdir().unwrap();
    let secret = b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
    // ~8 MiB nested payload: large enough that retaining the full decompressed
    // outer image would be a meaningful resident spike, small enough for CI.
    let mut inner_members = Vec::new();
    for i in 0..64 {
        inner_members.push((format!("inner/pad{i:02}.bin"), vec![b'A'; 128 * 1024]));
    }
    inner_members.push(("inner/secret.env".into(), secret.to_vec()));
    let inner = gzip_tar(&inner_members);

    let mut outer_members = Vec::new();
    for i in 0..16 {
        outer_members.push((format!("outer/pad{i:02}.bin"), vec![b'B'; 128 * 1024]));
    }
    outer_members.push(("outer/nested.tar.gz".into(), inner));
    let outer = gzip_tar(&outer_members);
    std::fs::write(dir.path().join("outer.tar.gz"), outer).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.iter().all(|error| {
            let msg = error.to_string();
            !msg.contains("archive-bomb guard") && !msg.contains("zip-bomb guard")
        }),
        "large nested corpus must stay under the default bomb budget; errors={errors:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("AKIAIOSFODNN7EXAMPLE")),
        "nested secret must remain findable through streaming nested tar.gz extraction"
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.contains("nested.tar.gz") && path.contains("secret.env"))
        }),
        "finding path must retain the nested archive chain"
    );
}

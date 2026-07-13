//! Regression lock for the always-on filesystem **tarball entry** path
//! (`extract::process_entry` -> `compressed::emit_tar_entries`).
//!
//! A secret committed inside a `.tar` / `.tgz` (docker layer export, helm
//! chart, npm/source release tarball, the dominant Linux/cloud archive) must
//! be unpacked per-entry and delivered with the exact `container//entry` inner
//! path, and the extractor must be decompression-bomb safe (Law 15): an entry
//! whose declared uncompressed size exceeds the per-file cap is refused,
//! counted, and NOT scanned, while the surrounding benign entries still
//! surface (the bomb guard is bounded, never all-or-nothing).
//!
//! Every assertion pins a concrete value: the exact archive `source_type`, the
//! exact `container//entry` metadata path, exact chunk counts, and the exact
//! over-cap error string. Plain `.tar` uses the default 100 MiB cap (its
//! container is tiny); the too-large-entry / boundary cases use a `.tgz` whose
//! compressed container passes the container-size gate but whose declared entry
//! size straddles a small `--max-file-size`, which is the real decompression-
//! bomb shape.
//!
//! Sibling coverage: `regression_private_key_in_compressed_archive` (the
//! `.tgz`/`.gz` private-key byte-intactness half) and
//! `regression_decompression_bomb_and_oom_caps` (the aggregate-budget half).

#![cfg(unix)]

mod support;

use keyhog_core::{Chunk, Source};
use keyhog_sources::FilesystemSource;
use support::archive::{gzip_bytes, tar_with_entries, tar_with_file};
use support::split_chunk_results;

const ARCHIVE_TYPE: &str = "filesystem/archive";

/// A unique text secret used as the "did the entry surface?" oracle. The chunk
/// layer delivers raw bytes, so surfacing == this sentinel appearing in an
/// archive chunk's data (detection is a separate layer, not under test here).
const SECRET: &str = "AWS_SECRET_ACCESS_KEY=KEYHOGtarSENTINELalpha0123456789abcdefUVWX\n";
const SECRET_MARKER: &str = "KEYHOGtarSENTINELalpha0123456789abcdefUVWX";

/// Write `bytes` under `name` in a fresh temp dir, scan it with the given
/// per-file cap (None = default 100 MiB), and return the emitted chunks plus
/// the stringified errors. The `TempDir` is returned so it outlives the scan.
fn scan(
    name: &str,
    bytes: &[u8],
    max_file_size: Option<u64>,
) -> (tempfile::TempDir, Vec<Chunk>, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(name), bytes).unwrap();
    let mut source = FilesystemSource::new(dir.path().to_path_buf());
    if let Some(cap) = max_file_size {
        source = source.with_max_file_size(cap);
    }
    let rows: Vec<_> = source.chunks().collect();
    let (chunk_refs, error_refs) = split_chunk_results(&rows);
    let chunks: Vec<Chunk> = chunk_refs.into_iter().cloned().collect();
    let errors: Vec<String> = error_refs.into_iter().map(|e| e.to_string()).collect();
    (dir, chunks, errors)
}

fn archive_chunks(chunks: &[Chunk]) -> Vec<&Chunk> {
    chunks
        .iter()
        .filter(|c| c.metadata.source_type.as_ref() == ARCHIVE_TYPE)
        .collect()
}

/// A `max_file_size` cap small enough that a 20 000-byte declared entry is over
/// the per-file cap, yet large enough that the compressed `.tgz` container and
/// the fully-materialised inner tar both stay under it / under the 4x budget.
const SMALL_CAP: u64 = 10_000;

/// Build a `.tgz` (gzipped tar) whose first entry is a small benign secret and
/// whose second entry declares a 20 000-byte body of `filler`: highly
/// compressible so the on-disk `.tgz` is a few hundred bytes (passes the
/// container-size gate) but the inner entry is over `SMALL_CAP`.
fn tgz_small_secret_plus_oversized(filler_marker: &str) -> Vec<u8> {
    let mut big = filler_marker
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(20_000)
        .collect::<Vec<u8>>();
    big.truncate(20_000);
    let tar = tar_with_entries(&[
        ("app/config/secret.pem", SECRET.as_bytes()),
        ("payload/big.bin", &big),
    ]);
    gzip_bytes(&tar)
}

// ── plain .tar: a secret entry surfaces with exact metadata ───────────────────

#[test]
fn secret_in_tar_entry_surfaces_as_archive_chunk() {
    let tar = tar_with_file("app/config/secret.pem", SECRET.as_bytes());
    let (_d, chunks, _errs) = scan("bundle.tar", &tar, None);
    let carrier = archive_chunks(&chunks)
        .into_iter()
        .find(|c| c.data.contains(SECRET_MARKER));
    assert!(
        carrier.is_some(),
        "a secret inside a .tar entry must surface as a `{ARCHIVE_TYPE}` chunk; got source_types {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.source_type.as_ref())
            .collect::<Vec<_>>()
    );
}

#[test]
fn tar_entry_yields_exactly_one_archive_chunk_for_secret() {
    let tar = tar_with_file("app/config/secret.pem", SECRET.as_bytes());
    let (_d, chunks, _errs) = scan("bundle.tar", &tar, None);
    let n = archive_chunks(&chunks)
        .iter()
        .filter(|c| c.data.contains(SECRET_MARKER))
        .count();
    assert_eq!(n, 1, "the secret must surface in exactly one archive chunk");
}

#[test]
fn tar_entry_path_is_container_double_slash_entry() {
    let tar = tar_with_file("app/config/secret.pem", SECRET.as_bytes());
    let (_d, chunks, _errs) = scan("bundle.tar", &tar, None);
    let carrier = archive_chunks(&chunks)
        .into_iter()
        .find(|c| c.data.contains(SECRET_MARKER))
        .expect("secret archive chunk");
    let path = carrier
        .metadata
        .path
        .as_deref()
        .expect("archive entry chunk carries an inner path");
    assert!(
        path.ends_with("bundle.tar//app/config/secret.pem"),
        "inner path must be `<container>//<entry>`; got {path:?}"
    );
    assert!(
        path.contains("//"),
        "the container/entry boundary marker `//` must be present; got {path:?}"
    );
}

#[test]
fn nested_dir_tar_entry_path_preserved() {
    let entry = "srv/etc/keys/deep/nested/id.pem";
    let tar = tar_with_file(entry, SECRET.as_bytes());
    let (_d, chunks, _errs) = scan("release.tar", &tar, None);
    let carrier = archive_chunks(&chunks)
        .into_iter()
        .find(|c| c.data.contains(SECRET_MARKER))
        .expect("deep-nested secret archive chunk");
    let path = carrier.metadata.path.as_deref().unwrap_or("");
    assert!(
        path.ends_with(&format!("release.tar//{entry}")),
        "the full nested directory entry path must be preserved; got {path:?}"
    );
}

#[test]
fn two_tar_entries_both_surface() {
    let second = SECRET.replace(SECRET_MARKER, "SECONDtarKEYsentinel987654321ZYXwvutsRQ");
    let tar = tar_with_entries(&[
        ("a/first.pem", SECRET.as_bytes()),
        ("b/second.pem", second.as_bytes()),
    ]);
    let (_d, chunks, _errs) = scan("two.tar", &tar, None);
    let arch = archive_chunks(&chunks);
    assert!(
        arch.iter().any(|c| c.data.contains(SECRET_MARKER)),
        "first entry must surface"
    );
    assert!(
        arch.iter()
            .any(|c| c.data.contains("SECONDtarKEYsentinel987654321ZYXwvutsRQ")),
        "second entry must surface"
    );
}

#[test]
fn tar_entry_secret_arrives_only_via_archive_source_type() {
    // The secret must be delivered by the unpack path, never by a raw whole-file
    // read of the .tar container.
    let tar = tar_with_file("app/config/secret.pem", SECRET.as_bytes());
    let (_d, chunks, _errs) = scan("bundle.tar", &tar, None);
    let carriers: Vec<&str> = chunks
        .iter()
        .filter(|c| c.data.contains(SECRET_MARKER))
        .map(|c| c.metadata.source_type.as_ref())
        .collect();
    assert_eq!(
        carriers,
        vec![ARCHIVE_TYPE],
        "secret must arrive via exactly one archive chunk, not a raw read"
    );
}

// ── directory / non-file entries produce no chunk ─────────────────────────────

#[test]
fn tar_directory_entry_yields_zero_archive_chunks() {
    // A tar containing ONLY a directory entry (structural metadata, no content)
    // must yield no archive chunks (the dir header is skipped, not scanned).
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "config/", std::io::empty())
            .unwrap();
        builder.finish().unwrap();
    }
    let (_d, chunks, _errs) = scan("dironly.tar", &buf, None);
    assert_eq!(
        archive_chunks(&chunks).len(),
        0,
        "a directory-only tar must yield zero archive chunks"
    );
}

#[test]
fn dot_tar_without_ustar_magic_is_not_untarred() {
    // Adversarial: a plain-text file misnamed `.tar` lacks the ustar/GNU magic,
    // so `looks_like_tar` refuses to untar it; it is scanned as a plain file and
    // never produces a `filesystem/archive` chunk.
    let junk = b"this is not a tar archive, just text pretending to be one\n";
    let (_d, chunks, _errs) = scan("fake.tar", junk, None);
    assert_eq!(
        archive_chunks(&chunks).len(),
        0,
        "a non-tar file misnamed .tar must not be untarred into archive chunks"
    );
}

// ── empty archives -> zero ────────────────────────────────────────────────────

#[test]
fn empty_tgz_yields_zero_chunks() {
    // A gzipped empty tar (1024 end-of-archive zero blocks) has zero entries, so
    // the whole scan yields zero chunks.
    let empty_tgz = gzip_bytes(&tar_with_entries(&[]));
    let (_d, chunks, errors) = scan("empty.tgz", &empty_tgz, None);
    assert_eq!(chunks.len(), 0, "an empty .tgz must yield zero chunks");
    assert_eq!(
        errors.len(),
        0,
        "an empty (well-formed) .tgz is not an error, just empty; got {errors:?}"
    );
}

#[test]
fn empty_bare_tar_yields_zero_archive_chunks() {
    let empty_tar = tar_with_entries(&[]);
    let (_d, chunks, _errs) = scan("empty.tar", &empty_tar, None);
    assert_eq!(
        archive_chunks(&chunks).len(),
        0,
        "an empty bare .tar must yield zero archive chunks"
    );
}

// ── decompression-bomb safety: oversized entry is bounded (Law 15) ────────────

#[test]
fn oversized_tgz_entry_content_is_not_scanned() {
    let bytes = tgz_small_secret_plus_oversized("BOMBPAYLOADmarkerX");
    let (_d, chunks, _errs) = scan("bomb.tgz", &bytes, Some(SMALL_CAP));
    let leaked = chunks.iter().any(|c| c.data.contains("BOMBPAYLOADmarkerX"));
    assert!(
        !leaked,
        "an entry whose declared size exceeds the per-file cap must NOT be scanned into a chunk"
    );
}

#[test]
fn oversized_tgz_entry_emits_exact_over_cap_error() {
    let bytes = tgz_small_secret_plus_oversized("BOMBPAYLOADmarkerX");
    let (_d, _chunks, errors) = scan("bomb.tgz", &bytes, Some(SMALL_CAP));
    let over_cap = errors.iter().find(|e| {
        e.contains("uncompressed size 20000 exceeds per-file cap 10000; entry was not scanned")
    });
    assert!(
        over_cap.is_some(),
        "the over-cap entry must surface the exact bounded-extraction error (Law 10/15); got {errors:?}"
    );
    let msg = over_cap.unwrap();
    assert!(
        msg.contains("payload/big.bin"),
        "the over-cap error must name the refused entry; got {msg:?}"
    );
}

#[test]
fn benign_entry_survives_alongside_oversized_entry() {
    // The bomb guard must bound only the oversized entry, not truncate the whole
    // archive: the small benign secret in the same .tgz still surfaces.
    let bytes = tgz_small_secret_plus_oversized("BOMBPAYLOADmarkerX");
    let (_d, chunks, _errs) = scan("bomb.tgz", &bytes, Some(SMALL_CAP));
    let n = archive_chunks(&chunks)
        .iter()
        .filter(|c| c.data.contains(SECRET_MARKER))
        .count();
    assert_eq!(
        n, 1,
        "the small benign entry must still surface exactly once despite a sibling over-cap entry"
    );
}

#[test]
fn tgz_entry_at_exact_cap_boundary_surfaces() {
    // Boundary: the per-file cap is strict `>` (`entry_size > max_size`), so an
    // entry whose declared size EQUALS the cap is scanned, not refused.
    let marker = "BOUNDARYcapEqualsSentinelZZ";
    let mut body = marker
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(SMALL_CAP as usize)
        .collect::<Vec<u8>>();
    body.truncate(SMALL_CAP as usize);
    assert_eq!(
        body.len(),
        SMALL_CAP as usize,
        "entry is exactly at the cap"
    );
    let tgz = gzip_bytes(&tar_with_file("edge/at_cap.txt", &body));
    let (_d, chunks, _errs) = scan("edge.tgz", &tgz, Some(SMALL_CAP));
    assert!(
        archive_chunks(&chunks)
            .iter()
            .any(|c| c.data.contains(marker)),
        "an entry whose size equals the cap (not greater) must still surface"
    );
}

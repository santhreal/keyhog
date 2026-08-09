//! An archive MEMBER's container format is decided by its own bytes, not by its
//! name.
//!
//! The bug: format inference for embedded members was extension-only.
//! `compressed_member_format` looked at the member name's extension,
//! `entry_is_embedded_tar` required a literal `.tar`, and
//! `entry_is_embedded_openpack_archive` required a `.zip`/`.jar`/... So a member
//! carrying the exact same bytes under a name with no recognized extension was
//! never decompressed or descended into. It fell through to the printable-strings
//! leaf, and compressed container bytes contain no 8-character printable run, so
//! the member produced NO chunk, NO error, and NO coverage gap. A secret in the
//! payload read as clean.
//!
//! That naming is the normal case, not an edge case. An OCI/Docker image layer is
//! stored under its digest (`sha256_<hex>`, `layer`, `blob`) with no suffix at
//! all, so every layer of every container image was invisible. Rotated logs and
//! backups drop the suffix too, and build outputs ship as `payload` / `data`.
//!
//! Every test below is a PAIR over byte-identical payloads: a control member whose
//! name carries the extension (which always worked) and a digest/bare-named member
//! with the same bytes (which silently found nothing). Both must now find the
//! secret, and the recovered member text must be identical.
//!
//! The last two tests pin the other half of the fix: a member that is a container
//! this in-memory dispatcher genuinely cannot open (7z / RAR / ar) must surface an
//! uncovered region instead of reading as clean, and a two-level OCI-shaped
//! `image.tar//<digest>` = gzip(tar(secret)) must reach the secret.

#![cfg(unix)]

mod support;

use keyhog_core::{Chunk, Source, SourceError};
use keyhog_sources::FilesystemSource;
use support::archive::{
    build_seven_zip, encode_xz, gzip_bytes, tar_with_entries, tar_with_file, zip_with_entries,
};
use support::split_chunk_results;

/// A high-entropy AWS secret-key literal: the detector-independent sentinel the
/// scanner-side corpus fires on, and long enough that no printable-strings
/// fallback could reconstruct it from compressed bytes.
const SECRET: &[u8] = b"AWS_SECRET_ACCESS_KEY = kQ7pR2xLm9vTzB4nWc6eYd8sHj3uFa1gPo5iN0bX\n";
const SENTINEL: &str = "kQ7pR2xLm9vTzB4nWc6eYd8sHj3uFa1gPo5iN0bX";

fn scan(name: &str, bytes: &[u8]) -> (Vec<Chunk>, Vec<String>) {
    let dir = tempfile::tempdir().expect("fixture dir");
    std::fs::write(dir.path().join(name), bytes).expect("write fixture");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    (
        chunks.into_iter().cloned().collect(),
        errors.iter().map(|error| error.to_string()).collect(),
    )
}

/// The recovered text of every chunk that carries the sentinel, joined. Empty
/// when the payload was never scanned, which is exactly the silent-clean shape.
fn recovered(chunks: &[Chunk]) -> String {
    chunks
        .iter()
        .filter(|chunk| chunk.data.contains(SENTINEL))
        .map(|chunk| chunk.data.as_ref())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Assert that a control member name and a bare/digest member name carrying the
/// SAME bytes both recover the secret, with identical recovered text.
fn assert_name_independent(
    container: &str,
    build: impl Fn(&str) -> Vec<u8>,
    control_member: &str,
    bare_member: &str,
) {
    let (control_chunks, control_errors) = scan(container, &build(control_member));
    let control = recovered(&control_chunks);
    assert!(
        !control.is_empty(),
        "control member {control_member} must recover the payload \
         (chunks={control_chunks:?} errors={control_errors:?})"
    );

    let (bare_chunks, bare_errors) = scan(container, &build(bare_member));
    let bare = recovered(&bare_chunks);
    assert!(
        !bare.is_empty(),
        "member {bare_member} carries the SAME bytes as {control_member} and must \
         recover the same payload; an unnamed container must not read as clean \
         (chunks={bare_chunks:?} errors={bare_errors:?})"
    );
    assert_eq!(
        control, bare,
        "recovered text must not depend on the member name"
    );
}

#[test]
fn gzip_member_of_a_tar_is_decompressed_without_a_gz_extension() {
    assert_name_independent(
        "release.tar",
        |member| tar_with_file(member, &gzip_bytes(SECRET)),
        "secret.txt.gz",
        "payload",
    );
}

#[test]
fn zstd_member_of_a_tar_is_decompressed_without_a_zst_extension() {
    let zstd = zstd::encode_all(SECRET, 3).expect("zstd encode");
    assert_name_independent(
        "release.tar",
        |member| tar_with_file(member, &zstd),
        "secret.txt.zst",
        "blob",
    );
}

#[test]
fn xz_member_of_a_tar_is_decompressed_without_an_xz_extension() {
    let xz = encode_xz(SECRET);
    assert_name_independent(
        "release.tar",
        |member| tar_with_file(member, &xz),
        "secret.txt.xz",
        "dump",
    );
}

#[test]
fn bzip2_member_of_a_tar_is_decompressed_without_a_bz2_extension() {
    use std::io::Write as _;
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(SECRET).expect("bzip2 write");
    let bz2 = encoder.finish().expect("bzip2 finish");
    assert_name_independent(
        "release.tar",
        |member| tar_with_file(member, &bz2),
        "secret.txt.bz2",
        "archive0",
    );
}

#[test]
fn tar_member_of_a_tar_is_untarred_without_a_tar_extension() {
    let inner = tar_with_file("creds.txt", SECRET);
    assert_name_independent(
        "image.tar",
        |member| tar_with_file(member, &inner),
        "layer.tar",
        // The literal shape of an OCI layer blob: a digest, no extension.
        "sha256_9f2c4a1b8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928170",
    );
}

#[test]
fn zip_member_of_a_tar_is_unzipped_without_a_zip_extension() {
    let inner = zip_with_entries(&[("creds.txt", SECRET)]);
    assert_name_independent(
        "bundle.tar",
        |member| tar_with_file(member, &inner),
        "app.zip",
        "bundle",
    );
}

#[test]
fn gzip_member_of_a_zip_is_decompressed_without_a_gz_extension() {
    let gz = gzip_bytes(SECRET);
    assert_name_independent(
        "release.zip",
        |member| zip_with_entries(&[(member, gz.as_slice())]),
        "secret.txt.gz",
        "payload",
    );
}

#[test]
fn tar_member_of_a_zip_is_untarred_without_a_tar_extension() {
    let inner = tar_with_file("creds.txt", SECRET);
    assert_name_independent(
        "image.zip",
        |member| zip_with_entries(&[(member, inner.as_slice())]),
        "layer.tar",
        "sha256_deadbeef00112233445566778899aabbccddeeff0011223344556677",
    );
}

#[test]
fn oci_shaped_gzipped_tar_layer_reaches_a_secret_two_levels_down() {
    // The real container-image shape: an image tar whose members are digest-named
    // gzipped tars. The secret is two containers deep and the only name in the
    // chain that carries an extension is the outer `image.tar`.
    let layer = gzip_bytes(&tar_with_entries(&[
        ("etc/hostname", b"builder".as_slice()),
        ("root/.aws/credentials", SECRET),
    ]));
    let (chunks, errors) = scan(
        "image.tar",
        &tar_with_file(
            "sha256_1122334455667788990011223344556677889900112233445566778899",
            &layer,
        ),
    );
    let text = recovered(&chunks);
    assert!(
        !text.is_empty(),
        "a secret inside a digest-named gzipped tar layer must be scanned \
         (chunks={chunks:?} errors={errors:?})"
    );
    // The inner member path must survive both hops so the finding is actionable.
    let path = chunks
        .iter()
        .find(|chunk| chunk.data.contains(SENTINEL))
        .and_then(|chunk| chunk.metadata.path.clone())
        .expect("member provenance path");
    assert!(
        path.contains("sha256_1122334455") && path.contains("root/.aws/credentials"),
        "member provenance must name both the layer digest and the inner file, got {path}"
    );
}

#[test]
fn seven_zip_member_without_an_extractor_is_reported_as_an_uncovered_region() {
    // 7z (like RAR and ar) needs a seekable file on disk, so the in-memory member
    // dispatcher cannot open it. Before, such a member fell through to the
    // printable-strings leaf, produced nothing, and read as clean. It must now be
    // a visible uncovered region naming the container family.
    //
    // THIS TEST GOES RED IF SOMEONE IMPROVES THE PRODUCT, so read the failure
    // before deleting it. Adding an in-memory 7z/RAR/ar extractor is a WIN, and it
    // makes this assertion false: the member would then be extracted rather than
    // reported as uncovered. The correct response in that case is to rewrite this
    // test to assert the member's CONTENTS are recovered (the shape every
    // `assert_name_independent` pair above already uses), and to drop the family
    // from `crate::magic::uninterpreted_container_format`. The wrong response is
    // to delete the test, which would retire the only guard proving an
    // un-openable container is never silently swallowed.
    let seven_zip = build_seven_zip(&[("creds.txt", SECRET)]);
    let (chunks, errors) = scan("bundle.tar", &tar_with_file("payload", &seven_zip));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("7z") && error.contains("were not scanned")),
        "an uninterpretable 7z member must surface an uncovered region, got errors={errors:?} \
         chunks={chunks:?}. If an in-memory 7z extractor was just added, this test must be \
         rewritten to assert the member's contents are RECOVERED, not deleted."
    );
}

#[test]
fn a_plain_text_member_is_still_scanned_and_reports_no_container_gap() {
    // Guard against the signature probe misfiring: ordinary members must be
    // unaffected, with no spurious uncovered-region error.
    let (chunks, errors) = scan("plain.tar", &tar_with_file("notes.txt", SECRET));
    assert!(
        !recovered(&chunks).is_empty(),
        "plain member must be scanned"
    );
    assert!(
        !errors
            .iter()
            .any(|error| error.contains("were not scanned")),
        "a plain text member must not report an uncovered region, got {errors:?}"
    );
}

/// The uncovered-region error is the operator-visible half of the fix, so it must
/// be a `SourceError` row rather than a silently counted skip.
#[test]
fn uncovered_container_region_is_an_error_row_not_a_dropped_member() {
    let seven_zip = build_seven_zip(&[("creds.txt", SECRET)]);
    let dir = tempfile::tempdir().expect("fixture dir");
    std::fs::write(
        dir.path().join("bundle.tar"),
        tar_with_file("blob", &seven_zip),
    )
    .expect("write fixture");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<Result<Chunk, SourceError>> = source.chunks().collect();
    assert!(
        rows.iter().any(|row| row.is_err()),
        "the member the dispatcher declined to interpret must appear as an Err row"
    );
}

// ===========================================================================
// The same extension-only inference existed one level up, on the plain
// filesystem entry. `process_entry` routes containers by extension, so a file
// with NO extension reached no extractor: it was prefix-sniffed, classified
// binary, and counted as a generic binary skip. An OCI layer blob on disk
// (`blobs/sha256/<hex>` in a registry cache or an extracted `docker save`) is
// exactly that shape, so its whole contents went unread.
// ===========================================================================

/// Scan a directory holding one file, so the walker's own dispatch runs.
fn scan_named(name: &str, bytes: &[u8]) -> (Vec<Chunk>, Vec<String>) {
    scan(name, bytes)
}

fn assert_extension_independent_on_disk(bytes: &[u8], control_name: &str, bare_name: &str) {
    let (control_chunks, control_errors) = scan_named(control_name, bytes);
    let control = recovered(&control_chunks);
    assert!(
        !control.is_empty(),
        "control file {control_name} must recover the payload \
         (chunks={control_chunks:?} errors={control_errors:?})"
    );

    let (bare_chunks, bare_errors) = scan_named(bare_name, bytes);
    let bare = recovered(&bare_chunks);
    assert!(
        !bare.is_empty(),
        "file {bare_name} holds the SAME bytes as {control_name} and must recover \
         the same payload; an extensionless container must not read as clean \
         (chunks={bare_chunks:?} errors={bare_errors:?})"
    );
    assert_eq!(
        control, bare,
        "recovered text must not depend on the file name"
    );
}

#[test]
fn extensionless_gzip_file_on_disk_is_decompressed() {
    assert_extension_independent_on_disk(
        &gzip_bytes(SECRET),
        "secret.txt.gz",
        "blobs_sha256_4f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a6978",
    );
}

#[test]
fn extensionless_tar_file_on_disk_is_untarred() {
    assert_extension_independent_on_disk(
        &tar_with_file("root/.aws/credentials", SECRET),
        "layer.tar",
        "layer",
    );
}

#[test]
fn extensionless_zip_file_on_disk_is_unzipped() {
    assert_extension_independent_on_disk(
        &zip_with_entries(&[("creds.txt", SECRET)]),
        "app.zip",
        "payload",
    );
}

#[test]
fn extensionless_gzipped_tar_layer_on_disk_reaches_the_inner_file() {
    // The on-disk OCI layer: a digest-named gzip whose payload is a tar. Two
    // hops, and no name in the chain carries an extension.
    let layer = gzip_bytes(&tar_with_file("root/.aws/credentials", SECRET));
    let (chunks, errors) = scan_named(
        "sha256_aabbccddeeff00112233445566778899aabbccddeeff0011",
        &layer,
    );
    assert!(
        !recovered(&chunks).is_empty(),
        "a digest-named gzipped tar layer on disk must be scanned \
         (chunks={chunks:?} errors={errors:?})"
    );
}

#[test]
fn extensionless_plain_text_file_is_still_scanned_as_text() {
    // Guard: the signature probe must not change how an ordinary extensionless
    // text file (`Dockerfile`, `Makefile`, `credentials`) is handled.
    let (chunks, errors) = scan_named("credentials", SECRET);
    assert!(
        !recovered(&chunks).is_empty(),
        "an extensionless text file must still be scanned (errors={errors:?})"
    );
}

#[test]
fn extensionless_non_container_binary_is_still_skipped() {
    // Guard the other side: an extensionless binary that is NOT a container must
    // stay a binary skip, not be routed to an extractor. An ELF header followed
    // by NUL padding has no container signature and no printable run.
    //
    // This assertion's success value (no chunks, no errors) is byte-identical to
    // what a harness that never ran would produce, so it is worthless on its own.
    // The control below runs FIRST, through the same helper and the same walker
    // path, and proves this scan can see a file when there is one to see. Without
    // it, `scan_named` silently returning nothing would read as a pass.
    let (control_chunks, _) = scan_named("plainfile", SECRET);
    assert!(
        !control_chunks.is_empty(),
        "control: scan_named must emit a chunk for an extensionless text file, \
         otherwise the emptiness asserted below proves nothing"
    );

    let mut elf = b"\x7fELF\x02\x01\x01\x00".to_vec();
    elf.resize(2048, 0);
    let (chunks, errors) = scan_named("a.out", &elf);
    assert!(
        chunks.is_empty() && errors.is_empty(),
        "a non-container extensionless binary must stay a silent-but-counted \
         binary skip, got chunks={chunks:?} errors={errors:?}"
    );
}

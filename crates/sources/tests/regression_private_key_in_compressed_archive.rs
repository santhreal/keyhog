//! #138 cross-source lock (compressed-container half): a MULTI-LINE private key
//! inside a gzipped tarball (`.tgz` / `.tar.gz`: the dominant npm/release
//! package format) OR a bare gzipped file (`*.gz`) must be decompressed and
//! delivered byte-intact, exactly like the plain zip/tar case.
//!
//! The compressed path is distinct: bytes are gzip-decompressed first, then
//! either untarred (tarball) or scanned as a single decompressed leaf, both
//! emit `filesystem/archive` chunks. If decompression reflowed or split the key
//! block the `private-key` / `putty-private-key` detector could never match, so
//! a key shipped in a release tarball would silently fall through. These tests
//! assert the whole block (begin/header → interior → end/MAC) survives.
//!
//! Plain zip/tar is covered by `regression_private_key_blocks_in_archives`;
//! git history by `regression_private_key_in_git_history`.

#![cfg(unix)]

mod support;

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use support::archive::{gzip_bytes, tgz_with_entries};
use support::split_chunk_results;

const PEM_INTERIOR_SENTINEL: &str = "KEYHOGtgzPEMbodysentinel0123456789abcDEFghij";
const PEM_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3UzRe60Sgbw7Szrwkw4I97rbfs7+bvtt8ZAs9uO+Qz502eyS
m1Nr2kJ8oP1q6Yc3v9wXr4tH5sN0bQ2dE7fG8hI9jK0lM1nO2pP3qR4sT5uV6wX
KEYHOGtgzPEMbodysentinel0123456789abcDEFghijklmnopqrstuvwxyz0123
7yZ8aB9cD0eF1gH2iJ3kL4mN5oP6qR7sT8uV9wX0yZ1aB2cD3eF4gH5iJ6kL7mN8
-----END RSA PRIVATE KEY-----
";

const PPK_MAC: &str = "8a1b2c3d4e5f60718293a4b5c6d7e8f901234567";
const PPK_KEY: &str = "PuTTY-User-Key-File-2: ssh-ed25519
Encryption: none
Comment: deploy-key-prod
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIGZ3aWxsbm90bWF0Y2hhbnl0aGluZ3JlYWxhdGE
xyZ0123456789abcdefABCDEFghijklmnopqrstuvWXYZ+/aSecondPublicLine
Private-Lines: 1
AAAAIHByaXZhdGVibG9iZ29lc2hlcmVrZXlob2dwcGtzZWNyZXRtYXRlcmlhbDAx
Private-MAC: 8a1b2c3d4e5f60718293a4b5c6d7e8f901234567
";

fn scan_archive(name: &str, bytes: &[u8]) -> (tempfile::TempDir, Vec<keyhog_core::Chunk>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(name), bytes).unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunk_refs, _errors) = split_chunk_results(&rows);
    (dir, chunk_refs.into_iter().cloned().collect())
}

fn unpacked_text(chunks: &[keyhog_core::Chunk]) -> String {
    chunks
        .iter()
        .filter(|c| c.metadata.source_type.as_ref() == "filesystem/archive")
        .map(|c| c.data.as_ref())
        .collect::<Vec<_>>()
        .join("\n")
}

fn archive_chunk_with<'a>(
    chunks: &'a [keyhog_core::Chunk],
    needle: &str,
) -> Option<&'a keyhog_core::Chunk> {
    chunks.iter().find(|c| {
        c.metadata.source_type.as_ref() == "filesystem/archive" && c.data.contains(needle)
    })
}

/// A bare `.gz` of a single file decompresses to ONE leaf chunk tagged
/// `filesystem/compressed` (not `filesystem/archive`, which is for tar/zip
/// entries) (see `extract_compressed_chunks`. These helpers target that leaf).
fn compressed_chunk_with<'a>(
    chunks: &'a [keyhog_core::Chunk],
    needle: &str,
) -> Option<&'a keyhog_core::Chunk> {
    chunks.iter().find(|c| {
        c.metadata.source_type.as_ref() == "filesystem/compressed" && c.data.contains(needle)
    })
}

fn decompressed_text(chunks: &[keyhog_core::Chunk]) -> String {
    chunks
        .iter()
        .filter(|c| c.metadata.source_type.as_ref() == "filesystem/compressed")
        .map(|c| c.data.as_ref())
        .collect::<Vec<_>>()
        .join("\n")
}

fn tgz(entry: &str, body: &str) -> Vec<u8> {
    tgz_with_entries(&[(entry, body.as_bytes())])
}

// ── PEM inside a .tgz tarball ─────────────────────────────────────────────────

#[test]
fn pem_in_tgz_surfaces_as_archive_chunk() {
    let (_d, chunks) = scan_archive("release.tgz", &tgz("pkg/id_rsa.pem", PEM_KEY));
    assert!(
        archive_chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").is_some(),
        "a PEM inside a .tgz must be decompressed+untarred; got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.source_type.as_ref())
            .collect::<Vec<_>>()
    );
}

#[test]
fn pem_in_tgz_block_is_byte_intact() {
    let (_d, chunks) = scan_archive("release.tgz", &tgz("pkg/id_rsa.pem", PEM_KEY));
    assert!(
        unpacked_text(&chunks).contains(PEM_KEY.trim_end()),
        "full PEM block survives the tgz path"
    );
}

#[test]
fn pem_in_tgz_preserves_interior_newlines() {
    let (_d, chunks) = scan_archive("release.tgz", &tgz("k.pem", PEM_KEY));
    let chunk = archive_chunk_with(&chunks, PEM_INTERIOR_SENTINEL).expect("pem chunk");
    let begin = chunk.data.find("-----BEGIN RSA PRIVATE KEY-----").unwrap();
    let end = chunk.data.find("-----END RSA PRIVATE KEY-----").unwrap();
    assert!(
        chunk.data[begin..end].matches('\n').count() >= 4,
        "interior line breaks preserved"
    );
}

#[test]
fn pem_in_tgz_has_begin_and_end_markers() {
    let (_d, chunks) = scan_archive("release.tgz", &tgz("k.pem", PEM_KEY));
    let text = unpacked_text(&chunks);
    assert!(text.contains("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(text.contains("-----END RSA PRIVATE KEY-----"));
}

#[test]
fn pem_in_tgz_interior_body_line_present() {
    let (_d, chunks) = scan_archive("release.tgz", &tgz("k.pem", PEM_KEY));
    assert!(
        unpacked_text(&chunks).contains(PEM_INTERIOR_SENTINEL),
        "no mid-block truncation"
    );
}

#[test]
fn pem_in_tgz_nested_entry_path_preserved() {
    let entry = "package/lib/keys/id_rsa.pem";
    let (_d, chunks) = scan_archive("npm-pkg.tgz", &tgz(entry, PEM_KEY));
    let chunk = archive_chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").expect("pem chunk");
    assert!(
        chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.contains(entry)),
        "deep tgz entry path preserved; got {:?}",
        chunk.metadata.path
    );
}

#[test]
fn pem_in_tgz_is_archive_chunk_not_raw_binary() {
    let (_d, chunks) = scan_archive("release.tgz", &tgz("k.pem", PEM_KEY));
    let carriers: Vec<&str> = chunks
        .iter()
        .filter(|c| c.data.contains(PEM_INTERIOR_SENTINEL))
        .map(|c| c.metadata.source_type.as_ref())
        .collect();
    assert!(!carriers.is_empty(), "the key must be found");
    assert!(
        carriers.iter().all(|st| *st == "filesystem/archive"),
        "the key must arrive via unpacking, not a raw read; got {carriers:?}"
    );
}

#[test]
fn crlf_pem_in_tgz_survives() {
    let crlf = PEM_KEY.replace('\n', "\r\n");
    let (_d, chunks) = scan_archive("release.tgz", &tgz("crlf.pem", &crlf));
    let text = unpacked_text(&chunks);
    assert!(text.contains("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(text.contains(PEM_INTERIOR_SENTINEL));
}

#[test]
fn extensionless_key_entry_in_tgz_surfaces() {
    let (_d, chunks) = scan_archive("keys.tgz", &tgz("id_rsa", PEM_KEY));
    assert!(
        unpacked_text(&chunks).contains(PEM_KEY.trim_end()),
        "extensionless entry surfaces"
    );
}

// ── PuTTY .ppk inside a .tgz ──────────────────────────────────────────────────

#[test]
fn ppk_in_tgz_surfaces() {
    let (_d, chunks) = scan_archive("release.tgz", &tgz("deploy.ppk", PPK_KEY));
    assert!(archive_chunk_with(&chunks, "PuTTY-User-Key-File-2:").is_some());
}

#[test]
fn ppk_in_tgz_block_is_byte_intact() {
    let (_d, chunks) = scan_archive("release.tgz", &tgz("deploy.ppk", PPK_KEY));
    assert!(unpacked_text(&chunks).contains(PPK_KEY.trim_end()));
}

#[test]
fn ppk_in_tgz_trailing_mac_present() {
    let (_d, chunks) = scan_archive("release.tgz", &tgz("deploy.ppk", PPK_KEY));
    assert!(unpacked_text(&chunks).contains(&format!("Private-MAC: {PPK_MAC}")));
}

// ── multi-entry tgz ───────────────────────────────────────────────────────────

#[test]
fn pem_and_ppk_in_same_tgz_both_surface() {
    let bytes = tgz_with_entries(&[
        ("a/id_rsa.pem", PEM_KEY.as_bytes()),
        ("b/deploy.ppk", PPK_KEY.as_bytes()),
    ]);
    let (_d, chunks) = scan_archive("bundle.tgz", &bytes);
    let text = unpacked_text(&chunks);
    assert!(text.contains(PEM_INTERIOR_SENTINEL), "PEM entry surfaces");
    assert!(
        text.contains("PuTTY-User-Key-File-2:"),
        ".ppk entry surfaces"
    );
}

#[test]
fn two_pem_entries_in_tgz_both_surface() {
    let second = PEM_KEY.replace(
        PEM_INTERIOR_SENTINEL,
        "SECONDtgzKEYsentinel987654321ZYXwvuts",
    );
    let bytes = tgz_with_entries(&[
        ("first.pem", PEM_KEY.as_bytes()),
        ("second.pem", second.as_bytes()),
    ]);
    let (_d, chunks) = scan_archive("two.tgz", &bytes);
    let text = unpacked_text(&chunks);
    assert!(text.contains(PEM_INTERIOR_SENTINEL), "first key surfaces");
    assert!(
        text.contains("SECONDtgzKEYsentinel987654321ZYXwvuts"),
        "second key surfaces"
    );
}

#[test]
fn key_among_benign_entries_in_tgz_surfaces() {
    let bytes = tgz_with_entries(&[
        ("package.json", b"{\"name\":\"pkg\"}\n"),
        ("README.md", b"# pkg\n"),
        ("ssl/id_rsa.pem", PEM_KEY.as_bytes()),
        ("index.js", b"module.exports = {};\n"),
    ]);
    let (_d, chunks) = scan_archive("npm.tgz", &bytes);
    assert!(
        unpacked_text(&chunks).contains(PEM_INTERIOR_SENTINEL),
        "key surfaces among package files"
    );
}

// ── bare .gz (single gzipped file, not a tarball) ─────────────────────────────

#[test]
fn gzipped_pem_file_surfaces() {
    let (_d, chunks) = scan_archive("id_rsa.pem.gz", &gzip_bytes(PEM_KEY.as_bytes()));
    assert!(
        compressed_chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").is_some(),
        "a bare gzipped PEM file must be decompressed and scanned (filesystem/compressed)"
    );
}

#[test]
fn gzipped_pem_block_is_byte_intact() {
    let (_d, chunks) = scan_archive("id_rsa.pem.gz", &gzip_bytes(PEM_KEY.as_bytes()));
    assert!(
        decompressed_text(&chunks).contains(PEM_KEY.trim_end()),
        "bare .gz preserves the PEM block"
    );
}

#[test]
fn gzipped_pem_preserves_newlines() {
    let (_d, chunks) = scan_archive("id_rsa.pem.gz", &gzip_bytes(PEM_KEY.as_bytes()));
    let chunk = compressed_chunk_with(&chunks, PEM_INTERIOR_SENTINEL).expect("pem chunk");
    assert!(
        chunk.data.matches('\n').count() >= 4,
        "bare .gz keeps key line breaks"
    );
}

#[test]
fn gzipped_ppk_file_surfaces() {
    let (_d, chunks) = scan_archive("deploy.ppk.gz", &gzip_bytes(PPK_KEY.as_bytes()));
    let text = decompressed_text(&chunks);
    assert!(
        text.contains("PuTTY-User-Key-File-2:"),
        "bare gzipped .ppk surfaces"
    );
    assert!(
        text.contains(&format!("Private-MAC: {PPK_MAC}")),
        "MAC present"
    );
}

// ── negatives / robustness ────────────────────────────────────────────────────

#[test]
fn benign_tgz_has_no_private_key_marker() {
    let bytes = tgz_with_entries(&[
        ("a.txt", b"nothing secret\n"),
        ("b.json", b"{\"ok\":true}\n"),
    ]);
    let (_d, chunks) = scan_archive("benign.tgz", &bytes);
    assert!(
        archive_chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").is_none(),
        "a key-free tgz must not fabricate a private-key marker"
    );
}

#[test]
fn empty_tgz_does_not_panic_and_yields_no_key() {
    let (_d, chunks) = scan_archive("empty.tgz", &tgz_with_entries(&[]));
    assert!(archive_chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").is_none());
}

#[test]
fn non_gzip_named_tgz_does_not_panic() {
    // Random bytes named .tgz: gzip decode fails (surfaced as an error, Law 10),
    // no archive chunk, and crucially no panic (we reach this line).
    let junk: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let (_d, chunks) = scan_archive("bad.tgz", &junk);
    assert!(archive_chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").is_none());
}

#[test]
fn pem_in_tar_gz_double_extension_surfaces() {
    // The other common naming (`release.tar.gz`, not `.tgz`) routes through the
    // `.gz` branch then untars (it must surface the key just the same).
    let (_d, chunks) = scan_archive("release.tar.gz", &tgz("id_rsa.pem", PEM_KEY));
    assert!(
        unpacked_text(&chunks).contains(PEM_INTERIOR_SENTINEL),
        "a .tar.gz (double extension) must also surface its key"
    );
}

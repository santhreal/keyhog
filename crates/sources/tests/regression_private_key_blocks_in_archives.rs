//! #138 cross-source lock: a MULTI-LINE private-key block (PEM and PuTTY `.ppk`)
//! planted inside an archive must be unpacked and delivered byte-intact, so the
//! (separately-locked) `private-key` / `putty-private-key` detectors can fire on
//! it.
//!
//! #121 proved a single-LINE secret in a zip entry surfaces. Private keys are
//! different and higher-stakes: they are multi-LINE blocks (`-----BEGIN…` →
//! base64 body → `-----END…`, or `PuTTY-User-Key-File-…` → `Private-Lines` →
//! `Private-MAC`). If archive unpacking dropped, reflowed, or split the interior
//! newlines, the detector's structural regex would never match and the most
//! severe class of secret would silently fall through. These tests assert the
//! complete block: BEGIN/header, every interior line, and END/MAC, arrives in
//! one `filesystem/archive` chunk byte-for-byte, newlines preserved.
//!
//! Detection of the block itself is locked elsewhere (`pem_private_key_recall_64`,
//! `regression_putty_private_key`, `regression_ssh2_private_key`); the source
//! delivering the intact block is the necessary-and-sufficient missing half.

#![cfg(unix)]

mod support;

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use support::archive::{tar_with_entries, zip_with_entries};
use support::split_chunk_results;

/// A multi-line PEM RSA private key. The interior line carries a sentinel so a
/// test can prove the BODY (not just the markers) survived unpacking.
const PEM_INTERIOR_SENTINEL: &str = "KEYHOGpemBODYsentinelLINEzzzz0123456789abcDEF";
const PEM_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3UzRe60Sgbw7Szrwkw4I97rbfs7+bvtt8ZAs9uO+Qz502eyS
m1Nr2kJ8oP1q6Yc3v9wXr4tH5sN0bQ2dE7fG8hI9jK0lM1nO2pP3qR4sT5uV6wX
KEYHOGpemBODYsentinelLINEzzzz0123456789abcDEFghijklmnopqrstuvwxy
7yZ8aB9cD0eF1gH2iJ3kL4mN5oP6qR7sT8uV9wX0yZ1aB2cD3eF4gH5iJ6kL7mN8
oP9qR0sT1uV2wX3yZ4aB5cD6eF7gH8iJ9kL0mN1oP2qR3sT4uV5wX6yZ7aB8cD9e
-----END RSA PRIVATE KEY-----";

/// A minimal unencrypted v2 PuTTY `.ppk`. The `Private-Lines` body is the secret
/// material; the trailing `Private-MAC` hex closes the structural match.
const PPK_MAC: &str = "8a1b2c3d4e5f60718293a4b5c6d7e8f901234567";
const PPK_KEY: &str = "PuTTY-User-Key-File-2: ssh-ed25519
Encryption: none
Comment: deploy-key-prod
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIGZ3aWxsbm90bWF0Y2hhbnl0aGluZ3JlYWxhdGE
xyZ0123456789abcdefABCDEFghijklmnopqrstuvWXYZ+/aSecondPublicLine
Private-Lines: 1
AAAAIHByaXZhdGVibG9iZ29lc2hlcmVrZXlob2dwcGtzZWNyZXRtYXRlcmlhbDAx
Private-MAC: 8a1b2c3d4e5f60718293a4b5c6d7e8f901234567";

/// Write `bytes` to `name` in a fresh tempdir and scan it; return the owned
/// chunks so callers can assert without borrow gymnastics.
fn scan_archive(name: &str, bytes: &[u8]) -> (tempfile::TempDir, Vec<keyhog_core::Chunk>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(name), bytes).unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunk_refs, _errors) = split_chunk_results(&rows);
    let chunks = chunk_refs.into_iter().cloned().collect();
    (dir, chunks)
}

/// All `filesystem/archive` chunk bodies concatenated (the unpacked text).
fn unpacked_text(chunks: &[keyhog_core::Chunk]) -> String {
    chunks
        .iter()
        .filter(|c| c.metadata.source_type.as_ref() == "filesystem/archive")
        .map(|c| c.data.as_ref())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The single archive chunk whose unpacked text contains `needle`.
fn archive_chunk_with<'a>(
    chunks: &'a [keyhog_core::Chunk],
    needle: &str,
) -> Option<&'a keyhog_core::Chunk> {
    chunks.iter().find(|c| {
        c.metadata.source_type.as_ref() == "filesystem/archive" && c.data.contains(needle)
    })
}

fn zip_of(entry: &str, body: &str) -> Vec<u8> {
    zip_with_entries(&[(entry, body.as_bytes())])
}
fn tar_of(entry: &str, body: &str) -> Vec<u8> {
    tar_with_entries(&[(entry, body.as_bytes())])
}

// ── PEM in a ZIP ─────────────────────────────────────────────────────────────

#[test]
fn pem_in_zip_surfaces_as_archive_chunk() {
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("secrets/id_rsa.pem", PEM_KEY));
    assert!(
        archive_chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").is_some(),
        "a PEM inside a zip must be unpacked into a filesystem/archive chunk; got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.source_type.as_ref())
            .collect::<Vec<_>>()
    );
}

#[test]
fn pem_in_zip_block_is_byte_intact() {
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("secrets/id_rsa.pem", PEM_KEY));
    assert!(
        unpacked_text(&chunks).contains(PEM_KEY),
        "the FULL multi-line PEM block must survive unpacking byte-for-byte"
    );
}

#[test]
fn pem_in_zip_preserves_interior_newlines() {
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("k.pem", PEM_KEY));
    let chunk = archive_chunk_with(&chunks, PEM_INTERIOR_SENTINEL).expect("pem chunk");
    let block_start = chunk.data.find("-----BEGIN RSA PRIVATE KEY-----").unwrap();
    let block_end = chunk.data.find("-----END RSA PRIVATE KEY-----").unwrap();
    let block = &chunk.data[block_start..block_end];
    assert!(
        block.contains('\n'),
        "the unpacked key block must retain its newlines"
    );
    assert!(
        block.matches('\n').count() >= 5,
        "all interior base64 lines must be present (>=5 newlines), got {}",
        block.matches('\n').count()
    );
}

#[test]
fn pem_in_zip_interior_body_line_present() {
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("k.pem", PEM_KEY));
    assert!(
        unpacked_text(&chunks).contains(PEM_INTERIOR_SENTINEL),
        "an interior base64 line must survive, no mid-block truncation"
    );
}

#[test]
fn pem_in_zip_has_both_begin_and_end_markers() {
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("k.pem", PEM_KEY));
    let text = unpacked_text(&chunks);
    assert!(text.contains("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(
        text.contains("-----END RSA PRIVATE KEY-----"),
        "the END marker closes the block"
    );
}

#[test]
fn pem_in_zip_entry_path_uses_double_slash_separator() {
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("etc/ssl/server.pem", PEM_KEY));
    let chunk = archive_chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").expect("pem chunk");
    assert!(
        chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.contains(".zip//etc/ssl/server.pem")),
        "archive entry path must be <archive>//<entry>; got {:?}",
        chunk.metadata.path
    );
}

// ── PEM in a TAR ─────────────────────────────────────────────────────────────

#[test]
fn pem_in_tar_surfaces_as_archive_chunk() {
    let (_d, chunks) = scan_archive("keys.tar", &tar_of("secrets/id_rsa.pem", PEM_KEY));
    assert!(archive_chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").is_some());
}

#[test]
fn pem_in_tar_block_is_byte_intact() {
    let (_d, chunks) = scan_archive("keys.tar", &tar_of("secrets/id_rsa.pem", PEM_KEY));
    assert!(
        unpacked_text(&chunks).contains(PEM_KEY),
        "tar must also preserve the full PEM block"
    );
}

#[test]
fn pem_in_tar_preserves_interior_newlines() {
    let (_d, chunks) = scan_archive("keys.tar", &tar_of("k.pem", PEM_KEY));
    let chunk = archive_chunk_with(&chunks, PEM_INTERIOR_SENTINEL).expect("pem chunk");
    assert!(
        chunk.data.matches('\n').count() >= 6,
        "tar entry must keep every key line"
    );
}

// ── PuTTY .ppk in a ZIP ──────────────────────────────────────────────────────

#[test]
fn ppk_in_zip_surfaces_as_archive_chunk() {
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("deploy.ppk", PPK_KEY));
    assert!(
        archive_chunk_with(&chunks, "PuTTY-User-Key-File-2:").is_some(),
        "a .ppk inside a zip must be unpacked"
    );
}

#[test]
fn ppk_in_zip_block_is_byte_intact() {
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("deploy.ppk", PPK_KEY));
    assert!(
        unpacked_text(&chunks).contains(PPK_KEY),
        "the full .ppk file must survive intact"
    );
}

#[test]
fn ppk_in_zip_has_header_private_lines_and_mac() {
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("deploy.ppk", PPK_KEY));
    let text = unpacked_text(&chunks);
    // The three structural anchors the putty detector regex requires.
    assert!(
        text.contains("PuTTY-User-Key-File-2:"),
        "header anchor present"
    );
    assert!(
        text.contains("Private-Lines:"),
        "Private-Lines body marker present"
    );
    assert!(
        text.contains(&format!("Private-MAC: {PPK_MAC}")),
        "trailing Private-MAC present"
    );
}

#[test]
fn ppk_in_zip_preserves_multiline_structure() {
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("deploy.ppk", PPK_KEY));
    let chunk = archive_chunk_with(&chunks, "PuTTY-User-Key-File-2:").expect("ppk chunk");
    assert!(
        chunk.data.matches('\n').count() >= 7,
        "the .ppk's header/body/MAC lines must all be present"
    );
}

// ── PuTTY .ppk in a TAR ──────────────────────────────────────────────────────

#[test]
fn ppk_in_tar_surfaces_as_archive_chunk() {
    let (_d, chunks) = scan_archive("keys.tar", &tar_of("deploy.ppk", PPK_KEY));
    assert!(archive_chunk_with(&chunks, "PuTTY-User-Key-File-2:").is_some());
}

#[test]
fn ppk_in_tar_block_is_byte_intact() {
    let (_d, chunks) = scan_archive("keys.tar", &tar_of("deploy.ppk", PPK_KEY));
    assert!(
        unpacked_text(&chunks).contains(PPK_KEY),
        "tar must preserve the full .ppk file"
    );
}

#[test]
fn ppk_in_tar_trailing_mac_present() {
    let (_d, chunks) = scan_archive("keys.tar", &tar_of("deploy.ppk", PPK_KEY));
    assert!(unpacked_text(&chunks).contains(&format!("Private-MAC: {PPK_MAC}")));
}

// ── multi-entry / co-located / boundary cases ────────────────────────────────

#[test]
fn pem_and_ppk_in_same_zip_both_surface() {
    let zip = zip_with_entries(&[
        ("a/id_rsa.pem", PEM_KEY.as_bytes()),
        ("b/deploy.ppk", PPK_KEY.as_bytes()),
    ]);
    let (_d, chunks) = scan_archive("bundle.zip", &zip);
    let text = unpacked_text(&chunks);
    assert!(text.contains(PEM_KEY), "the PEM entry surfaces");
    assert!(text.contains(PPK_KEY), "the .ppk entry surfaces");
}

#[test]
fn two_pem_blocks_in_one_entry_both_present() {
    let second = PEM_KEY.replace(
        PEM_INTERIOR_SENTINEL,
        "SECONDpemBODYsentinel9876543210ZYXwvu",
    );
    let body = format!("{PEM_KEY}\n\n# next key\n\n{second}");
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("two_keys.pem", &body));
    let text = unpacked_text(&chunks);
    assert!(
        text.contains(PEM_INTERIOR_SENTINEL),
        "first key body present"
    );
    assert!(
        text.contains("SECONDpemBODYsentinel9876543210ZYXwvu"),
        "second key body present"
    );
    assert_eq!(
        text.matches("-----BEGIN RSA PRIVATE KEY-----").count(),
        2,
        "both BEGIN markers present"
    );
}

#[test]
fn key_alongside_benign_files_still_surfaces() {
    let zip = zip_with_entries(&[
        ("README.md", b"# project\nnothing to see here\n"),
        ("LICENSE", b"MIT\n"),
        ("config/id_rsa.pem", PEM_KEY.as_bytes()),
        ("data.json", b"{\"ok\":true}\n"),
    ]);
    let (_d, chunks) = scan_archive("repo.zip", &zip);
    assert!(
        unpacked_text(&chunks).contains(PEM_KEY),
        "the key entry surfaces among benign files"
    );
}

#[test]
fn deeply_nested_key_entry_path_is_preserved() {
    let entry = "home/deploy/.ssh/keys/prod/id_rsa.pem";
    let (_d, chunks) = scan_archive("keys.zip", &zip_of(entry, PEM_KEY));
    let chunk = archive_chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").expect("pem chunk");
    assert!(
        chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.contains(entry)),
        "the deep entry path must be preserved; got {:?}",
        chunk.metadata.path
    );
}

#[test]
fn pem_with_crlf_line_endings_survives_in_zip() {
    let crlf = PEM_KEY.replace('\n', "\r\n");
    let (_d, chunks) = scan_archive("keys.zip", &zip_of("crlf.pem", &crlf));
    let text = unpacked_text(&chunks);
    assert!(
        text.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "CRLF PEM begin marker survives"
    );
    assert!(
        text.contains(PEM_INTERIOR_SENTINEL),
        "CRLF PEM body line survives"
    );
    assert!(
        text.contains("-----END RSA PRIVATE KEY-----"),
        "CRLF PEM end marker survives"
    );
}

#[test]
fn pem_entry_without_extension_still_surfaces() {
    // The detector keys on the `-----BEGIN` marker, not the filename, so an
    // extensionless entry (e.g. an OpenSSH `id_rsa`) must still surface.
    let (_d, chunks) = scan_archive("keys.tar", &tar_of("id_rsa", PEM_KEY));
    assert!(
        unpacked_text(&chunks).contains(PEM_KEY),
        "an extensionless key entry surfaces"
    );
}

#[test]
fn ppk_as_only_entry_surfaces_intact() {
    let (_d, chunks) = scan_archive("only.zip", &zip_of("k.ppk", PPK_KEY));
    let text = unpacked_text(&chunks);
    assert!(
        text.contains("PuTTY-User-Key-File-2: ssh-ed25519"),
        "header line intact"
    );
    assert!(
        text.contains(PPK_KEY),
        "the sole .ppk entry is delivered whole"
    );
}

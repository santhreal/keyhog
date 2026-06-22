//! Gap-closure integration tests for `FilesystemSource`
//! (`crates/sources/src/filesystem.rs` + `filesystem/{filter,extract,read}`).
//!
//! Coverage axes for this file: symlink non-follow, hidden files/dirs,
//! `--max-file-size` cap, binary-extension / binary-magic skip, and the
//! `.keyhogignore` / ignore-pattern path. Every expected value is derived
//! from the real source:
//!
//!   * `walker_config` (filter.rs:197): `follow_symlinks(false)`,
//!     `skip_hidden(false)`, `respect_gitignore(true)`,
//!     `ignore_files([".keyhogignore"])`, `exclude_dirs(SKIP_DIRS)`,
//!     `exclude_extensions(SKIP_EXTENSIONS)`, `max_file_size(0)`.
//!   * `process_entry` (extract.rs:44) gate order:
//!       1. `is_default_excluded(filename)`  (filename component only)
//!       2. `.min.` / `.bundle.` / `.chunk.js` / `.min.js` / `.bundle.js`
//!       3. `max_size > 0 && file_size > max_size` -> warn + counter + return
//!       4. `skip_extensions().contains(ext.to_lowercase())`
//!       5. empty-ext: sniff first 16 bytes for NUL / ELF / MZ / %PDF / PK
//!       6. merkle skip
//!       7. pdf structured extraction
//!       8. archive (zip/apk/ipa/crx/jar) with symlink refusal
//!       9. compressed (gz/zst/lz4/sz)
//!      10. har
//!      11. windowed if `file_size > window_size`
//!      12. mmap/buffered text else `extract_printable_strings(_, 8)` fallback.
//!   * Source-level `with_max_file_size(0)` is "unlimited" because the gate
//!     is `max_size > 0 && ...`.
//!
//! The whole-directory walk applies the `exclude_extensions` / `exclude_dirs`
//! filter at walk time, so several of the `process_entry`-internal gates are
//! exercised through the deterministic single-file `with_include_paths` path
//! (which bypasses the walker's extension filter via `std::fs::metadata` +
//! `std::iter::once`), keeping each assertion attributable to keyhog's own
//! code rather than to codewalk internals.

use crate::support::collect_chunks;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{reset_skipped_over_max_size, skip_counts, FilesystemSource};
use std::fs;
use std::io::Write;
use std::path::Path;

// ─────────────────────────── helpers ───────────────────────────

/// Collect all successfully-emitted chunks from a source rooted at `dir`.
fn chunks_of(dir: &Path) -> Vec<keyhog_core::Chunk> {
    let source = FilesystemSource::new(dir.to_path_buf());
    collect_chunks(&source)
}

/// Concatenate every chunk's text so a body-substring assertion is robust to
/// chunk ordering (the walk is parallel and unordered).
fn combined_body(chunks: &[keyhog_core::Chunk]) -> String {
    chunks.iter().map(|c| c.data.to_string()).collect()
}

/// Scan a single explicitly-included file. This drives the
/// `with_include_paths` single-file branch (extract.rs path through
/// `std::fs::metadata` + `process_entry`), which bypasses the walker's
/// own extension/dir filter and thus isolates `process_entry`'s gates.
fn scan_single_file(path: &Path) -> Vec<keyhog_core::Chunk> {
    let source = FilesystemSource::new(
        path.parent()
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf(),
    )
    .with_include_paths(vec![path.to_path_buf()]);
    collect_chunks(&source)
}

// ───────────────────────── symlink non-follow ─────────────────────────

#[test]
#[cfg(unix)]
fn symlinked_regular_file_in_walk_is_not_followed() {
    // walker_config sets follow_symlinks(false). A symlink pointing at a
    // real file outside the walk must NOT be traversed: only the real
    // target file (which also lives in the tree) is scanned, exactly once.
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("real.env"), "TOKEN=real_target_value").unwrap();
    symlink(dir.path().join("real.env"), dir.path().join("alias.env")).unwrap();

    let chunks = chunks_of(dir.path());
    // Exactly one chunk: the real file. The symlink alias is not followed.
    assert_eq!(
        chunks.len(),
        1,
        "symlink alias must not produce a second chunk; paths: {:?}",
        chunks
            .iter()
            .filter_map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
    assert!(combined_body(&chunks).contains("TOKEN=real_target_value"));
}

#[test]
#[cfg(unix)]
fn symlink_to_external_secret_file_not_read_through_walk() {
    // Adversarial: a symlink inside the scan root points at a sensitive file
    // OUTSIDE the root (the classic `creds -> ~/.aws/credentials` link-swap).
    // With follow_symlinks(false) the walker never visits the link target,
    // so the external secret never enters a chunk.
    use std::os::unix::fs::symlink;
    let outside = tempfile::tempdir().unwrap();
    fs::write(
        outside.path().join("credentials"),
        "AWS_SECRET=EXTERNAL_SHOULD_NOT_BE_READ",
    )
    .unwrap();

    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("ok.txt"), "PUBLIC=inside_root").unwrap();
    symlink(
        outside.path().join("credentials"),
        root.path().join("creds.txt"),
    )
    .unwrap();

    let body = combined_body(&chunks_of(root.path()));
    assert!(body.contains("PUBLIC=inside_root"));
    assert!(
        !body.contains("EXTERNAL_SHOULD_NOT_BE_READ"),
        "follow_symlinks(false) must keep external symlink target out of scan"
    );
}

#[test]
#[cfg(unix)]
fn included_symlinked_plain_file_is_canonicalized_then_read() {
    // ASYMMETRY (documented behavior, NOT the same guard as the walk): the
    // --include single-file branch (filesystem.rs:246) maps each include path
    // through `p.canonicalize()`, which RESOLVES the symlink to its real
    // target BEFORE process_entry runs. So `open_file_safe`'s O_NOFOLLOW
    // never fires (the path it opens is already the non-symlink target), and
    // the target's bytes ARE read and emitted. This is the real behavior the
    // M17 HAR comment in extract.rs warns about for the include path. The
    // directory-walk path, by contrast, refuses symlinks via
    // follow_symlinks(false) (see symlink_to_external_secret_file_*). We pin
    // the actual outcome so a future change to the canonicalize-then-read
    // behavior is intentional.
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("secret_target.txt");
    fs::write(&target, "API_KEY=LINK_TARGET_SECRET_0001").unwrap();
    let link = dir.path().join("link.txt");
    symlink(&target, &link).unwrap();

    let chunks = scan_single_file(&link);
    assert_eq!(
        chunks.len(),
        1,
        "include path canonicalizes the symlink then reads the target"
    );
    assert!(chunks[0].data.contains("LINK_TARGET_SECRET_0001"));
}

#[test]
#[cfg(unix)]
fn symlinked_directory_in_walk_is_not_descended() {
    // A symlink to a directory full of secrets must not be descended:
    // follow_symlinks(false) means the linked subtree is invisible.
    use std::os::unix::fs::symlink;
    let secrets = tempfile::tempdir().unwrap();
    fs::write(
        secrets.path().join("buried.txt"),
        "BURIED=SHOULD_NOT_SURFACE_42",
    )
    .unwrap();

    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("top.txt"), "TOP=visible_99").unwrap();
    symlink(secrets.path(), root.path().join("linkdir")).unwrap();

    let body = combined_body(&chunks_of(root.path()));
    assert!(body.contains("TOP=visible_99"));
    assert!(
        !body.contains("SHOULD_NOT_SURFACE_42"),
        "symlinked directory must not be descended under follow_symlinks(false)"
    );
}

#[test]
#[cfg(unix)]
fn self_referential_symlink_loop_yields_only_real_files() {
    // Twin of the existing loop test but pinned to an exact count: a self
    // loop plus one real file must yield exactly one chunk (the real file)
    // and terminate.
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("only.env"), "ONLY=one_real_file").unwrap();
    symlink(dir.path(), nested.join("loop")).unwrap();

    let chunks = chunks_of(dir.path());
    assert_eq!(
        chunks.len(),
        1,
        "loop must not multiply the single real file"
    );
    assert!(chunks[0].data.contains("ONLY=one_real_file"));
}

// ───────────────────────── hidden files / dirs ─────────────────────────

#[test]
fn hidden_dotfile_is_scanned_because_skip_hidden_is_false() {
    // walker_config sets skip_hidden(false): a leading-dot file such as
    // `.env` is a prime credential location and MUST be scanned.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".env"), "SECRET=dotfile_secret_value").unwrap();

    let chunks = chunks_of(dir.path());
    assert_eq!(
        chunks.len(),
        1,
        "hidden .env must be scanned (skip_hidden=false)"
    );
    assert!(chunks[0].data.contains("SECRET=dotfile_secret_value"));
}

#[test]
fn hidden_subdirectory_contents_are_scanned() {
    // A non-excluded hidden directory (e.g. `.config`) is walked: its files
    // surface. `.git` is the excluded case (covered separately).
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join(".config");
    fs::create_dir_all(&hidden).unwrap();
    fs::write(hidden.join("creds.txt"), "TOKEN=in_dot_config_dir").unwrap();

    let body = combined_body(&chunks_of(dir.path()));
    assert!(
        body.contains("TOKEN=in_dot_config_dir"),
        "files under a non-excluded hidden dir must be scanned"
    );
}

#[test]
fn dot_git_directory_is_excluded() {
    // `.git` is in SKIP_DIRS (filter.rs) AND is a SKIP_SEGMENT in
    // is_default_excluded. A secret committed under .git/ must not be scanned.
    let dir = tempfile::tempdir().unwrap();
    let git = dir.path().join(".git");
    fs::create_dir_all(&git).unwrap();
    fs::write(git.join("config"), "GIT_INTERNAL=should_be_skipped_77").unwrap();
    fs::write(dir.path().join("app.env"), "APP=scanned_root_88").unwrap();

    let body = combined_body(&chunks_of(dir.path()));
    assert!(body.contains("APP=scanned_root_88"));
    assert!(
        !body.contains("should_be_skipped_77"),
        ".git tree must be excluded"
    );
}

#[test]
fn hidden_dotfile_with_secret_in_nested_visible_dir() {
    // Combine: hidden file inside an ordinary subdirectory. The dot prefix
    // alone never suppresses scanning.
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("svc");
    fs::create_dir_all(&sub).unwrap();
    fs::write(sub.join(".secrets"), "DB_PASS=hidden_nested_pw").unwrap();

    let body = combined_body(&chunks_of(dir.path()));
    assert!(body.contains("DB_PASS=hidden_nested_pw"));
}

// ───────────────────────── max-file-size cap ─────────────────────────

#[test]
fn oversize_plain_file_is_skipped_and_undersize_kept() {
    // process_entry gate: `max_size > 0 && file_size > max_size` returns
    // before any read. Under-cap sibling survives.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("small.txt"), "K=under_cap_marker").unwrap();
    let big = "BIG=".to_string() + &"y".repeat(4096);
    fs::write(dir.path().join("big.txt"), &big).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(512);
    let chunks = collect_chunks(&source);
    assert_eq!(chunks.len(), 1, "only the under-cap file should emit");
    assert!(chunks[0].data.contains("K=under_cap_marker"));
    assert!(
        !combined_body(&chunks).contains(&"y".repeat(64)),
        "oversize file bytes must not leak through the cap"
    );
}

#[test]
fn file_exactly_at_cap_is_kept() {
    // Boundary: gate is strictly `file_size > max_size`. A file whose size
    // equals the cap is NOT over the cap and must be scanned.
    let dir = tempfile::tempdir().unwrap();
    let content = b"ABCDEFGHIJ"; // exactly 10 bytes
    let path = dir.path().join("exact.txt");
    fs::write(&path, content).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), 10);

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(10);
    let chunks = collect_chunks(&source);
    assert_eq!(chunks.len(), 1, "file at exactly the cap must be kept");
    assert!(chunks[0].data.contains("ABCDEFGHIJ"));
}

#[test]
fn file_one_byte_over_cap_is_skipped() {
    // Boundary twin: size == cap + 1 trips `file_size > max_size`.
    let dir = tempfile::tempdir().unwrap();
    let content = b"ABCDEFGHIJK"; // 11 bytes
    fs::write(dir.path().join("over.txt"), content).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(10);
    let chunks = collect_chunks(&source);
    assert_eq!(chunks.len(), 0, "size == cap+1 must be skipped");
}

#[test]
fn max_file_size_zero_means_unlimited() {
    // The gate is `max_size > 0 && file_size > max_size`; with max_size == 0
    // the cap never triggers, so even a (relatively) large text file scans.
    let dir = tempfile::tempdir().unwrap();
    let content = "Z=".to_string() + &"z".repeat(10_000);
    fs::write(dir.path().join("a.txt"), &content).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(0);
    let chunks = collect_chunks(&source);
    assert_eq!(
        chunks.len(),
        1,
        "max_file_size(0) is unlimited, not skip-all"
    );
    assert!(chunks[0].data.contains("Z="));
}

#[test]
fn oversize_skip_increments_global_counter() {
    // process_entry bumps crate::SKIPPED_OVER_MAX_SIZE per over-cap file.
    // The counter is process-global and tests run in parallel, so we reset
    // then assert the count strictly increased by at least our own over-cap
    // file (>= 1) rather than an exact value that a concurrent test could
    // perturb.
    reset_skipped_over_max_size();
    let dir = tempfile::tempdir().unwrap();
    let big = "B=".to_string() + &"q".repeat(2048);
    fs::write(dir.path().join("toobig.txt"), &big).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(64);
    let _ = collect_chunks(&source);

    assert!(
        skip_counts().over_max_size >= 1,
        "the over-cap file must have bumped the skip counter"
    );
}

#[test]
fn cap_applies_to_included_single_file() {
    // The cap is checked inside process_entry, so it also covers the
    // explicit --include single-file path, not just the directory walk.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inc.txt");
    let big = "I=".to_string() + &"w".repeat(1000);
    fs::write(&path, &big).unwrap();

    let chunks: Vec<_> = collect_chunks(
        &FilesystemSource::new(dir.path().to_path_buf())
            .with_include_paths(vec![path.clone()])
            .with_max_file_size(128),
    )
    .into_iter()
    .collect();
    assert_eq!(chunks.len(), 0, "cap must apply on the include path too");
}

// ───────────────── binary skip: extension list ─────────────────

#[test]
fn binary_extension_png_skipped_via_include_path() {
    // SKIP_EXTENSIONS contains "png". A .png file routed through the include
    // path (bypassing the walker's own extension filter) is dropped by the
    // `skip_extensions().contains(ext)` gate in process_entry, even though
    // its bytes here are valid text.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("logo.png");
    fs::write(&path, "this is actually text not a png API_KEY=x").unwrap();

    let chunks = scan_single_file(&path);
    assert!(
        chunks.is_empty(),
        ".png is in SKIP_EXTENSIONS and must be skipped; got {} chunks",
        chunks.len()
    );
}

#[test]
fn binary_extension_match_is_case_insensitive() {
    // process_entry lowercases the extension before the SKIP_EXTENSIONS
    // lookup, so `.PNG` (uppercase) is treated identically to `.png`.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("IMAGE.PNG");
    fs::write(&path, "text content SECRET=should_not_emit").unwrap();

    let chunks = scan_single_file(&path);
    assert!(
        chunks.is_empty(),
        "uppercase .PNG must skip just like .png (ext lowercased)"
    );
}

#[test]
fn binary_extension_exe_skipped_via_include_path() {
    // "exe" is in SKIP_EXTENSIONS.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tool.exe");
    fs::write(&path, "MZ-but-as-text TOKEN=nope").unwrap();
    let chunks = scan_single_file(&path);
    assert!(chunks.is_empty(), ".exe must be skipped by extension");
}

#[test]
fn dot_bin_extension_skipped_via_include_path() {
    // "bin" is in SKIP_EXTENSIONS (disk images / firmware group).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("firmware.bin");
    fs::write(&path, "AKIA-looking text TOKEN=ignored").unwrap();
    let chunks = scan_single_file(&path);
    assert!(chunks.is_empty(), ".bin must be skipped by extension");
}

#[test]
fn safetensors_extension_skipped_via_include_path() {
    // "safetensors" (ML weights) is the last SKIP_EXTENSIONS entry.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("model.safetensors");
    fs::write(&path, "weights-as-text KEY=irrelevant").unwrap();
    let chunks = scan_single_file(&path);
    assert!(
        chunks.is_empty(),
        ".safetensors must be skipped by extension"
    );
}

#[test]
fn tar_archive_content_is_unpacked_and_scanned() {
    // AUD-capability-1: `.tar` is NO LONGER skipped purely on extension. A real
    // tarball is unpacked per-entry (mirroring the zip branch), so a secret
    // committed inside it is found and the chunk path is the inner
    // `<archive>//<entry>`. (`.tar` is the dominant Linux/cloud archive — docker
    // layer exports, helm charts, source tarballs — so skipping it was a
    // first-class recall hole.)
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.tar");

    // Build a genuine ustar tarball holding one file with a secret body.
    let mut builder = tar::Builder::new(Vec::new());
    let body = b"SECRET=found_inside_tar_entry";
    let mut header = tar::Header::new_ustar();
    header.set_path("leak.env").unwrap();
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &body[..]).unwrap();
    let tar_bytes = builder.into_inner().unwrap();
    fs::write(&path, &tar_bytes).unwrap();

    let chunks = scan_single_file(&path);
    assert!(
        !chunks.is_empty(),
        ".tar must be unpacked and its entries scanned, not skipped by extension"
    );
    let body = combined_body(&chunks);
    assert!(
        body.contains("SECRET=found_inside_tar_entry"),
        ".tar entry body must reach the scanner; got chunks: {chunks:#?}"
    );
    // The reported path is the inner archive entry, not the opaque container.
    assert!(
        chunks.iter().any(|c| c
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.contains("//leak.env"))),
        ".tar entry chunk must carry the `<archive>//<entry>` path; got chunks: {chunks:#?}"
    );
}

#[test]
fn zip_archive_default_excluded_entries_are_counted() {
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.zip");
    let file = fs::File::create(&path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("node_modules/hidden.env", opts).unwrap();
    zip.write_all(b"SECRET=excluded_from_archive").unwrap();
    zip.start_file("safe.env", opts).unwrap();
    zip.write_all(b"SECRET=scanned_from_archive").unwrap();
    zip.finish().unwrap();

    let chunks = scan_single_file(&path);
    let body = combined_body(&chunks);
    assert!(
        body.contains("SECRET=scanned_from_archive"),
        "non-excluded zip entry must still be scanned; got chunks: {chunks:#?}"
    );
    assert!(
        !body.contains("excluded_from_archive"),
        "default-excluded zip entry must not be scanned; got chunks: {chunks:#?}"
    );
    assert_eq!(
        skip_counts().excluded,
        1,
        "default-excluded archive entries must be counted as excluded coverage gaps"
    );
}

#[test]
fn ordinary_text_extension_is_scanned() {
    // Control: an extension NOT in SKIP_EXTENSIONS (.py) is scanned normally.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ok.py");
    fs::write(&path, "API_KEY = 'scanned_python_secret_01'").unwrap();
    let chunks = scan_single_file(&path);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].metadata.source_type, "filesystem");
    assert!(chunks[0].data.contains("scanned_python_secret_01"));
}

// ───────────────── binary skip: magic / NUL sniff (no extension) ─────────────────

#[test]
fn extensionless_elf_magic_is_skipped() {
    // process_entry: a file with NO extension sniffs the first 16 bytes;
    // a `\x7fELF` header is in the sniff list and is detected as binary and
    // skipped. Filename must be genuinely extension-less (`a.out` would have
    // ext "out" and bypass the sniff), so use a bare name.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("loader"); // no extension -> sniff runs
    let mut bytes = b"\x7fELF".to_vec();
    bytes.extend_from_slice(b"\x02\x01\x01\x00 padding API_KEY=elf");
    fs::write(&path, &bytes).unwrap();
    let chunks = scan_single_file(&path);
    assert!(
        chunks.is_empty(),
        "ELF-magic extensionless file must be skipped by the 16-byte sniff"
    );
}

#[test]
fn elf_magic_with_nonskip_extension_falls_back_to_strings_not_text() {
    // Twin of the above documenting the OTHER branch: a file named with a
    // non-SKIP extension (`.out`) keeps a non-empty `ext`, so the 16-byte
    // sniff is bypassed entirely. The bytes then hit the text decoder, whose
    // `has_binary_magic` rejects the `\x7fELF` header (returns None), and the
    // printable-strings fallback emits the embedded run tagged
    // `filesystem:binary-strings` -- it is NOT decoded as plain `filesystem`
    // text. This pins the asymmetry between the sniff (extension-less only)
    // and the magic check (always, in the decoder).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.out"); // ext "out", not in SKIP_EXTENSIONS
    let mut bytes = b"\x7fELF".to_vec();
    bytes.extend_from_slice(b"\x02\x01\x01\x00 padding API_KEY=elfmarker");
    fs::write(&path, &bytes).unwrap();
    let chunks = scan_single_file(&path);
    assert!(
        chunks
            .iter()
            .all(|c| c.metadata.source_type != "filesystem"),
        "ELF magic must keep the decoder from treating it as plain text"
    );
    assert!(
        chunks
            .iter()
            .any(|c| c.metadata.source_type == "filesystem:binary-strings"
                && c.data.contains("API_KEY=elfmarker")),
        "embedded printable run must surface via the binary-strings fallback"
    );
}

#[test]
fn extensionless_mz_magic_is_skipped() {
    // "MZ" header (PE/exe) detected by the sniff on an extensionless file.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("program"); // no extension
    let mut bytes = b"MZ".to_vec();
    bytes.extend_from_slice(b"\x90\x00\x03 padding KEY=mz");
    fs::write(&path, &bytes).unwrap();
    let chunks = scan_single_file(&path);
    assert!(
        chunks.is_empty(),
        "MZ-magic extensionless file must be skipped"
    );
}

#[test]
fn extensionless_pdf_magic_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("doc"); // no extension
    fs::write(&path, b"%PDF-1.7 binary stuff SECRET=pdf").unwrap();
    let chunks = scan_single_file(&path);
    assert!(
        chunks.is_empty(),
        "%PDF-magic extensionless file must be skipped"
    );
}

#[test]
fn extensionless_zip_magic_is_skipped_by_sniff() {
    // PK\x03\x04 (ZIP) is in the 16-byte sniff list. An extensionless file
    // with that header is skipped before any unpack attempt (the archive
    // branch keys off the .zip extension, which this file lacks).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive"); // no extension
    fs::write(&path, b"PK\x03\x04 zip-ish bytes TOKEN=pk").unwrap();
    let chunks = scan_single_file(&path);
    assert!(
        chunks.is_empty(),
        "PK magic extensionless file must be skipped"
    );
}

#[test]
fn extensionless_nul_byte_in_first_16_is_skipped() {
    // The sniff also rejects any of the first 16 bytes being NUL.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rawblob"); // no extension
    fs::write(&path, b"abc\x00def more text KEY=nul").unwrap();
    let chunks = scan_single_file(&path);
    assert!(
        chunks.is_empty(),
        "a NUL byte within the first 16 bytes must trip the binary sniff"
    );
}

#[test]
fn extensionless_clean_text_passes_the_sniff() {
    // Control: an extensionless file whose first 16 bytes are clean text
    // survives the sniff and is scanned as `filesystem`.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Makefile"); // no extension, clean text
    fs::write(&path, "CONFIG_TOKEN=clean_no_extension_value").unwrap();
    let chunks = scan_single_file(&path);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].metadata.source_type, "filesystem");
    assert!(chunks[0].data.contains("clean_no_extension_value"));
}

#[test]
fn extensionless_nul_after_first_16_bytes_is_not_caught_by_sniff() {
    // The sniff only inspects the FIRST 16 bytes. A NUL at byte 20 passes the
    // sniff; the file then goes to the text-read path where the full
    // `looks_binary` density check (read/decode.rs) decides. With a single
    // late NUL in otherwise-clean text the decoder's lenient NUL rule
    // (first_nul >= 1024 -> not auto-binary) keeps it, so it IS scanned.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes"); // no extension
    let mut bytes = b"clean leading sixteen bytes here ".to_vec(); // > 16 clean bytes
    bytes.extend_from_slice(b"and then KEY=late_nul_value");
    bytes.push(0x00); // single trailing NUL, well past byte 16 and < 1024
    fs::write(&path, &bytes).unwrap();
    let chunks = scan_single_file(&path);
    assert_eq!(
        chunks.len(),
        1,
        "a single late NUL must not trip the 16-byte sniff and survives decode"
    );
    assert!(chunks[0].data.contains("KEY=late_nul_value"));
}

// ───────────────── binary skip: density / strings fallback ─────────────────

#[test]
fn high_nul_density_binary_falls_back_to_printable_strings() {
    // A .dat file (not in SKIP_EXTENSIONS) with a dense binary body and an
    // embedded >=8-char printable run: text decode returns None (looks_binary
    // / early NUL), then extract_printable_strings(_, 8) fires and the chunk
    // is tagged `filesystem:binary-strings`.
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = vec![0u8; 32];
    bytes.extend_from_slice(b"AKIAFALLBACKSTRINGMARKER01");
    bytes.extend_from_slice(&[0u8; 32]);
    fs::write(dir.path().join("blob.dat"), &bytes).unwrap();

    let chunks = chunks_of(dir.path());
    assert!(
        chunks
            .iter()
            .any(|c| c.metadata.source_type == "filesystem:binary-strings"
                && c.data.contains("AKIAFALLBACKSTRINGMARKER01")),
        "binary body must surface via printable-strings fallback; got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.source_type.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn binary_with_only_short_runs_yields_no_chunk() {
    // extract_printable_strings uses min_len 8. A binary file whose printable
    // runs are all < 8 chars yields an empty strings vec -> process_entry
    // returns with no chunk, and must count that unscannable binary as a
    // coverage gap.
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().unwrap();
    // Each printable run ("abc", "de") is < 8 chars, separated by NULs.
    let bytes = b"abc\x00de\x00f\x00gh\x00ij\x00".to_vec();
    fs::write(dir.path().join("tiny.dat"), &bytes).unwrap();

    let chunks = chunks_of(dir.path());
    assert!(
        chunks.is_empty(),
        "binary with only <8-char runs must yield no chunk; got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.source_type.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        skip_counts().binary >= 1,
        "binary files with no printable scan chunk must be counted as skipped binary coverage"
    );
}

#[test]
fn pdf_magic_dat_file_not_scanned_as_text() {
    // A .dat file starting with %PDF- : has_binary_magic rejects it from the
    // text decoder; the only printable run >= 8 in a real magic header could
    // surface via the strings fallback, so assert it is NOT tagged plain
    // `filesystem` text (the recall-relevant contract: never decoded as text).
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("file.dat"),
        b"%PDF-1.4\n%binarygunk\x00\x01\x02",
    )
    .unwrap();
    let chunks = chunks_of(dir.path());
    assert!(
        chunks
            .iter()
            .all(|c| c.metadata.source_type != "filesystem"),
        "PDF-magic file must never be decoded as plain text"
    );
}

// ───────────────── .keyhogignore / ignore patterns ─────────────────

#[test]
fn keyhogignore_file_excludes_matching_path() {
    // walker_config registers `.keyhogignore` via ignore_files(). A pattern
    // in that file (gitignore syntax) must exclude the matching file from
    // the walk while leaving siblings scanned.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".keyhogignore"), "ignored.txt\n").unwrap();
    fs::write(dir.path().join("ignored.txt"), "SECRET=should_be_ignored").unwrap();
    fs::write(dir.path().join("kept.txt"), "SECRET=should_be_kept").unwrap();

    let body = combined_body(&chunks_of(dir.path()));
    assert!(body.contains("should_be_kept"));
    assert!(
        !body.contains("should_be_ignored"),
        ".keyhogignore pattern must exclude the listed file"
    );
}

#[test]
fn keyhogignore_glob_pattern_excludes_by_extension() {
    // Glob support: `*.secret` in .keyhogignore drops every .secret file.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".keyhogignore"), "*.secret\n").unwrap();
    fs::write(dir.path().join("a.secret"), "TOKEN=glob_excluded_a").unwrap();
    fs::write(dir.path().join("b.secret"), "TOKEN=glob_excluded_b").unwrap();
    fs::write(dir.path().join("c.txt"), "TOKEN=glob_kept_c").unwrap();

    let body = combined_body(&chunks_of(dir.path()));
    assert!(body.contains("glob_kept_c"));
    assert!(!body.contains("glob_excluded_a"));
    assert!(!body.contains("glob_excluded_b"));
}

#[test]
fn keyhogignore_directory_pattern_excludes_subtree() {
    // A directory pattern in .keyhogignore excludes the whole subtree.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".keyhogignore"), "fixtures/\n").unwrap();
    let fixtures = dir.path().join("fixtures");
    fs::create_dir_all(&fixtures).unwrap();
    fs::write(fixtures.join("data.txt"), "TOKEN=inside_fixtures_dir").unwrap();
    fs::write(dir.path().join("real.txt"), "TOKEN=outside_fixtures").unwrap();

    let body = combined_body(&chunks_of(dir.path()));
    assert!(body.contains("outside_fixtures"));
    assert!(
        !body.contains("inside_fixtures_dir"),
        "a directory pattern in .keyhogignore must exclude the subtree"
    );
}

#[test]
fn ignore_patterns_via_with_ignore_paths_exclude_file() {
    // with_ignore_paths feeds ignore_overrides into the walker. A bare
    // pattern is normalized to a leading-`!` override (filter.rs:204), which
    // codewalk treats as an exclusion. The named file must be dropped.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("drop_me.log"), "SECRET=excluded_by_flag").unwrap();
    fs::write(dir.path().join("keep_me.log"), "SECRET=kept_by_flag").unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf())
        .with_ignore_paths(vec!["**/drop_me.log".to_string()]);
    let body = combined_body(&collect_chunks(&source));
    assert!(body.contains("kept_by_flag"));
    assert!(
        !body.contains("excluded_by_flag"),
        "with_ignore_paths pattern must exclude the matching file"
    );
}

#[test]
fn respect_gitignore_false_still_scans_ignored_file() {
    // scan-system flips respect_gitignore(false). With it off, a file listed
    // in .gitignore (or .keyhogignore semantics via the same ignore engine)
    // is no longer hidden: the leaked key surfaces. Here we use a .gitignore
    // entry and prove the file IS scanned when respect_gitignore=false.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".gitignore"), "stash.txt\n").unwrap();
    fs::write(dir.path().join("stash.txt"), "LEAK=found_despite_gitignore").unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_respect_gitignore(false);
    let body = combined_body(&collect_chunks(&source));
    assert!(
        body.contains("found_despite_gitignore"),
        "respect_gitignore(false) must surface .gitignore'd files (scan-system mode)"
    );
}

#[test]
fn respect_gitignore_true_hides_gitignored_file() {
    // Default (true): a .gitignore'd file is excluded from the walk.
    // `.gitignore` only takes effect inside a git repository — the `ignore`
    // crate keys off a `.git` directory to locate the repo root before
    // applying gitignore rules. Mark this tempdir as a repo so the default
    // respect_gitignore(true) walk honors .gitignore (a bare temp dir with no
    // .git would scan the file, which the respect_gitignore(false) twin covers).
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(dir.path().join(".gitignore"), "stash.txt\n").unwrap();
    fs::write(dir.path().join("stash.txt"), "LEAK=hidden_by_gitignore").unwrap();
    fs::write(dir.path().join("visible.txt"), "OK=visible_default").unwrap();

    let body = combined_body(&chunks_of(dir.path()));
    assert!(body.contains("visible_default"));
    assert!(
        !body.contains("hidden_by_gitignore"),
        "default respect_gitignore(true) must hide .gitignore'd files"
    );
}

#[test]
fn keyhogignore_negation_reincludes_file() {
    // gitignore-style negation: ignore everything *.env then re-include one.
    // Verifies the ignore engine honors `!` negation through .keyhogignore.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".keyhogignore"), "*.env\n!keep.env\n").unwrap();
    fs::write(dir.path().join("drop.env"), "SECRET=dropped_env").unwrap();
    fs::write(dir.path().join("keep.env"), "SECRET=reincluded_env").unwrap();

    let body = combined_body(&chunks_of(dir.path()));
    assert!(
        body.contains("reincluded_env"),
        "`!keep.env` negation must re-include the file"
    );
    assert!(
        !body.contains("dropped_env"),
        "`*.env` must still drop the non-negated env file"
    );
}

// ───────────────── default-exclude filename gate (is_default_excluded) ─────────────────

#[test]
fn package_lock_json_excluded_by_filename() {
    // is_default_excluded matches the bare filename `package-lock.json`
    // (FILENAMES list). process_entry returns before reading it.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("package-lock.json");
    fs::write(&path, "{\"token\": \"SECRET=in_lockfile\"}").unwrap();
    // include path so the walker's own filtering isn't the thing under test.
    let chunks = scan_single_file(&path);
    assert!(
        chunks.is_empty(),
        "package-lock.json must be dropped by is_default_excluded"
    );
}

#[test]
fn min_js_excluded_by_filename_substring() {
    // process_entry second gate: filename containing `.min.` is dropped.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.min.js");
    fs::write(&path, "var SECRET='minified_secret'").unwrap();
    let chunks = scan_single_file(&path);
    assert!(chunks.is_empty(), ".min.js must be excluded");
}

#[test]
fn bundle_js_excluded_by_filename_substring() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vendor.bundle.js");
    fs::write(&path, "var SECRET='bundled_secret'").unwrap();
    let chunks = scan_single_file(&path);
    assert!(chunks.is_empty(), ".bundle.js must be excluded");
}

#[test]
fn chunk_js_suffix_excluded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("3.chunk.js");
    fs::write(&path, "var SECRET='chunked'").unwrap();
    let chunks = scan_single_file(&path);
    assert!(chunks.is_empty(), ".chunk.js suffix must be excluded");
}

#[test]
fn tsconfig_json_excluded_by_filename() {
    // is_default_excluded special-cases tsconfig*.json.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tsconfig.json");
    fs::write(&path, "{\"compilerOptions\": {\"key\":\"SECRET=tsc\"}}").unwrap();
    let chunks = scan_single_file(&path);
    assert!(chunks.is_empty(), "tsconfig.json must be excluded");
}

#[test]
fn dot_map_suffix_excluded() {
    // `.map` is a SUFFIX in is_default_excluded.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.js.map");
    fs::write(&path, "{\"mappings\":\"SECRET=sourcemap\"}").unwrap();
    let chunks = scan_single_file(&path);
    assert!(chunks.is_empty(), ".map suffix must be excluded");
}

#[test]
fn cargo_lock_filename_excluded_case_insensitive() {
    // FILENAMES is matched case-insensitively (`cargo.lock`). The real file
    // is `Cargo.lock`; is_default_excluded lowercases the comparison.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Cargo.lock");
    fs::write(&path, "name = \"SECRET=in_cargo_lock\"").unwrap();
    let chunks = scan_single_file(&path);
    assert!(
        chunks.is_empty(),
        "Cargo.lock must be excluded (case-insensitive filename match)"
    );
}

// ───────────────── metadata correctness on the text path ─────────────────

#[test]
fn scanned_text_chunk_carries_path_and_size_metadata() {
    // For a normal scanned file the chunk's metadata.path is populated and
    // size_bytes equals the on-disk length; source_type is "filesystem".
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("conf.txt");
    let content = "API_KEY=meta_check_value_123";
    fs::write(&path, content).unwrap();
    let size = fs::metadata(&path).unwrap().len();

    let chunks = chunks_of(dir.path());
    assert_eq!(chunks.len(), 1);
    let meta = &chunks[0].metadata;
    assert_eq!(meta.source_type, "filesystem");
    assert_eq!(meta.size_bytes, Some(size));
    assert!(meta.mtime_ns.is_some());
    let p = meta.path.as_deref().expect("path metadata must be set");
    assert!(
        p.ends_with("conf.txt"),
        "chunk path should end with the file name, got {p}"
    );
}

#[test]
fn empty_file_yields_no_chunk() {
    // A zero-byte file: read returns empty text, the binary fallback finds no
    // printable runs, and process_entry emits nothing.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("empty.txt"), b"").unwrap();
    let chunks = chunks_of(dir.path());
    assert!(chunks.is_empty(), "empty file must yield no chunk");
}

#[test]
fn name_is_filesystem() {
    // Source trait contract.
    let dir = tempfile::tempdir().unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    assert_eq!(source.name(), "filesystem");
}

// ───────────────── combined / cross-cutting ─────────────────

#[test]
fn mixed_tree_only_eligible_files_emit() {
    // One directory exercising several gates at once:
    //   - .env hidden text       -> scanned
    //   - image.png              -> skipped (extension, at walk time)
    //   - node_modules/secret.js -> skipped (excluded dir)
    //   - app.py                 -> scanned
    // Expect exactly 2 chunks (.env + app.py).
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".env"), "A=hidden_env_secret").unwrap();
    fs::write(dir.path().join("image.png"), [0x89, 0x50, 0x4e, 0x47]).unwrap();
    fs::write(dir.path().join("app.py"), "B=python_secret").unwrap();
    let nm = dir.path().join("node_modules");
    fs::create_dir_all(&nm).unwrap();
    fs::write(nm.join("secret.js"), "C=node_modules_secret").unwrap();

    let chunks = chunks_of(dir.path());
    assert_eq!(
        chunks.len(),
        2,
        "expected exactly .env + app.py; paths: {:?}",
        chunks
            .iter()
            .filter_map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
    let body = combined_body(&chunks);
    assert!(body.contains("hidden_env_secret"));
    assert!(body.contains("python_secret"));
    assert!(!body.contains("node_modules_secret"));
}

#[test]
fn nonexistent_root_yields_source_error_without_panic() {
    // A root that does not exist must not panic or flatten to "clean": the
    // iterator surfaces the unread root as a SourceError item.
    let missing = std::env::temp_dir().join("keyhog-gap-nonexistent-root-xyz-77");
    let _ = fs::remove_dir_all(&missing);
    let source = FilesystemSource::new(missing);
    let results: Vec<_> = source.chunks().collect();
    assert_eq!(results.len(), 1, "missing root must yield one error");
    assert!(
        results[0].is_err(),
        "missing root must yield SourceError, not content"
    );
}

#[test]
fn deeply_nested_real_directories_are_walked() {
    // Hidden-vs-deep coverage: deep but real (non-symlink) directories are
    // fully descended; the leaf file surfaces.
    let dir = tempfile::tempdir().unwrap();
    let mut p = dir.path().to_path_buf();
    for i in 0..20 {
        p = p.join(format!("d{i}"));
    }
    fs::create_dir_all(&p).unwrap();
    fs::write(p.join("leaf.txt"), "DEEP=leaf_secret_value").unwrap();

    let body = combined_body(&chunks_of(dir.path()));
    assert!(
        body.contains("DEEP=leaf_secret_value"),
        "deep real directory chain must be fully walked"
    );
}

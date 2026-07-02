//! Regression coverage for the `keyhog-sources` filesystem source's symlink
//! traversal-safety contract, focused on the link-swap exfiltration guard and
//! the walk-vs-`--include` ASYMMETRY. This file is deliberately distinct from
//! `regression_fs_walk_symlink.rs` (which pins the walker's cycle/plain-file
//! multiplicity and the `.zip`/`.tar` refusals): here we pin
//!   * the remaining expandable-archive extensions (`.gz`/`.7z`/`.rar`/`.pdf`/
//!     `.tgz`/`.har`) each refused LOUDLY during the walk-time archive-symlink
//!     audit (`filesystem.rs::collect_walk_archive_symlink_errors`);
//!   * name-based vs target-based expandable classification (an archive-NAMED
//!     link to a plain target, and a plain-NAMED link to an archive target, are
//!     BOTH refused; a dangling archive link is refused by name);
//!   * a plain symlink that ESCAPES the scan root is neither read nor falsely
//!     flagged as an archive;
//!   * the `--include` asymmetry (`filesystem.rs::chunks` include branch): a
//!     symlink to a PLAIN file is canonicalize-then-read, but a symlink whose
//!     link name OR resolved target is expandable is REFUSED with the
//!     include-specific wording.
//!
//! The exact refusal strings are read from source, not guessed:
//!   generic:  "refusing to scan archive symlink '<path>': archive symlink
//!              expansion is blocked to prevent link-swap exfiltration"
//!   har walk: "failed to scan HAR file '<path>': refusing to open archive at a
//!              symlink path; HAR file was not scanned"
//!   include:  "refusing to scan explicitly included archive symlink '<path>':
//!              archive symlink expansion is blocked to prevent link-swap
//!              exfiltration"
//!
//! Every assertion pins a concrete value (an exact count, an exact substring of
//! a refusal error, or an exact "scanned exactly once" multiplicity). No test
//! asserts only `!is_empty()`.

#![cfg(unix)]

use keyhog_core::{Chunk, Source, SourceError};
use keyhog_sources::FilesystemSource;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::symlink;

/// Drain a source, partitioning chunk rows from surfaced error rows. Several
/// symlink contracts INTENTIONALLY surface a `SourceError`; swallowing it would
/// hide the loud-refusal guarantee under test.
fn drain(src: &FilesystemSource) -> (Vec<Chunk>, Vec<SourceError>) {
    let mut chunks = Vec::new();
    let mut errors = Vec::new();
    for row in src.chunks() {
        match row {
            Ok(chunk) => chunks.push(chunk),
            Err(error) => errors.push(error),
        }
    }
    (chunks, errors)
}

/// Number of DISTINCT files (by recorded chunk path) whose scanned content
/// contains `needle`. Counts files, so "scanned exactly once" is a count of 1.
fn files_containing(chunks: &[Chunk], needle: &str) -> usize {
    let mut hit_paths: BTreeSet<String> = BTreeSet::new();
    for chunk in chunks {
        if chunk.data.contains(needle) {
            let path = chunk
                .metadata
                .path
                .clone()
                .unwrap_or_else(|| String::from("<no-path>"));
            hit_paths.insert(path);
        }
    }
    hit_paths.len()
}

/// Rendered error strings (via `Display`), for substring assertions.
fn error_strings(errors: &[SourceError]) -> Vec<String> {
    errors.iter().map(ToString::to_string).collect()
}

/// Count of error rows carrying the GENERIC archive-symlink refusal wording.
fn generic_archive_refusals(errors: &[SourceError]) -> usize {
    error_strings(errors)
        .iter()
        .filter(|m| {
            m.contains("archive symlink expansion is blocked to prevent link-swap exfiltration")
        })
        .count()
}

// ---------------------------------------------------------------------------
// Escaping plain symlink: neither read NOR falsely flagged as an archive
// ---------------------------------------------------------------------------

#[test]
fn walk_plain_symlink_escaping_root_is_neither_read_nor_flagged() {
    // A non-archive `.txt` symlink at the scan root points at a real file that
    // lives OUTSIDE the root. Following it would read an off-tree secret (the
    // link-swap class). The walker must NOT scan the target's content, and —
    // because the link is not archive-named/-targeted — it must NOT raise the
    // archive-symlink refusal either. A real in-root sibling still scans, so a
    // refused link never turns the walk into a no-op.
    let root_dir = tempfile::tempdir().unwrap();
    let outside_dir = tempfile::tempdir().unwrap();
    let secret = outside_dir.path().join("secret.txt");
    fs::write(&secret, "escaping_plain_symlink_marker_off_tree\n").unwrap();
    symlink(&secret, root_dir.path().join("escape.txt")).unwrap();
    fs::write(
        root_dir.path().join("healthy.txt"),
        "in_root_healthy_marker\n",
    )
    .unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root_dir.path().to_path_buf()));
    assert_eq!(
        files_containing(&chunks, "escaping_plain_symlink_marker_off_tree"),
        0,
        "an escaping plain symlink's off-tree target must never be scanned"
    );
    assert_eq!(
        generic_archive_refusals(&errors),
        0,
        "a plain (non-archive) escaping symlink must NOT raise an archive-symlink refusal: {errors:?}"
    );
    assert_eq!(
        files_containing(&chunks, "in_root_healthy_marker"),
        1,
        "the real in-root sibling is scanned exactly once despite the refused link"
    );
}

// ---------------------------------------------------------------------------
// Each expandable archive extension is refused LOUDLY during the walk audit
// ---------------------------------------------------------------------------

/// Plant an archive-extension symlink to an out-of-tree target under a fresh
/// root, walk it, and return the surfaced error strings.
fn refusal_strings_for_archive_link(link_name: &str) -> Vec<String> {
    let root_dir = tempfile::tempdir().unwrap();
    // `/etc/hostname` is a stable, always-present out-of-tree regular file; the
    // audit classifies by extension and never actually reads it.
    symlink("/etc/hostname", root_dir.path().join(link_name)).unwrap();
    let (_chunks, errors) = drain(&FilesystemSource::new(root_dir.path().to_path_buf()));
    error_strings(&errors)
}

#[test]
fn walk_gz_archive_symlink_refused_loudly_generic() {
    let joined = refusal_strings_for_archive_link("payload.gz");
    let refusal = joined
        .iter()
        .find(|m| {
            m.contains("archive symlink expansion is blocked to prevent link-swap exfiltration")
        })
        .unwrap_or_else(|| panic!("expected the loud generic refusal for .gz; got {joined:?}"));
    assert!(
        refusal.contains("payload.gz"),
        "the .gz archive-symlink refusal must name payload.gz, got: {refusal}"
    );
}

#[test]
fn walk_seven_zip_archive_symlink_refused_loudly_generic() {
    let joined = refusal_strings_for_archive_link("payload.7z");
    let refusal = joined
        .iter()
        .find(|m| {
            m.contains("archive symlink expansion is blocked to prevent link-swap exfiltration")
        })
        .unwrap_or_else(|| panic!("expected the loud generic refusal for .7z; got {joined:?}"));
    assert!(
        refusal.contains("payload.7z"),
        "the .7z archive-symlink refusal must name payload.7z, got: {refusal}"
    );
}

#[test]
fn walk_rar_archive_symlink_refused_loudly_generic() {
    let joined = refusal_strings_for_archive_link("payload.rar");
    let refusal = joined
        .iter()
        .find(|m| {
            m.contains("archive symlink expansion is blocked to prevent link-swap exfiltration")
        })
        .unwrap_or_else(|| panic!("expected the loud generic refusal for .rar; got {joined:?}"));
    assert!(
        refusal.contains("payload.rar"),
        "the .rar archive-symlink refusal must name payload.rar, got: {refusal}"
    );
}

#[test]
fn walk_pdf_archive_symlink_refused_loudly_generic() {
    let joined = refusal_strings_for_archive_link("payload.pdf");
    let refusal = joined
        .iter()
        .find(|m| {
            m.contains("archive symlink expansion is blocked to prevent link-swap exfiltration")
        })
        .unwrap_or_else(|| panic!("expected the loud generic refusal for .pdf; got {joined:?}"));
    assert!(
        refusal.contains("payload.pdf"),
        "the .pdf archive-symlink refusal must name payload.pdf, got: {refusal}"
    );
}

#[test]
fn walk_tgz_archive_symlink_refused_loudly_generic() {
    // `.tgz` is expandable but is NOT the `tar`/`har` special-cased wording, so
    // it takes the generic branch of `archive_symlink_error`.
    let joined = refusal_strings_for_archive_link("payload.tgz");
    let refusal = joined
        .iter()
        .find(|m| {
            m.contains("archive symlink expansion is blocked to prevent link-swap exfiltration")
        })
        .unwrap_or_else(|| panic!("expected the loud generic refusal for .tgz; got {joined:?}"));
    assert!(
        refusal.contains("payload.tgz"),
        "the .tgz archive-symlink refusal must name payload.tgz, got: {refusal}"
    );
}

#[test]
fn walk_har_archive_symlink_refused_with_har_specific_message() {
    // The `.har` branch of `archive_symlink_error` emits a HAR-specific refusal
    // distinct from the generic archive wording.
    let joined = refusal_strings_for_archive_link("capture.har");
    let refusal = joined
        .iter()
        .find(|m| m.contains("refusing to open archive at a symlink path"))
        .unwrap_or_else(|| panic!("expected the HAR-specific refusal; got {joined:?}"));
    assert!(
        refusal.contains("capture.har")
            && refusal.contains("failed to scan HAR file")
            && refusal.contains("HAR file was not scanned"),
        "HAR symlink refusal must name capture.har with the HAR-specific wording, got: {refusal}"
    );
}

// ---------------------------------------------------------------------------
// Name-based vs target-based classification; dangling-link fail-closed
// ---------------------------------------------------------------------------

#[test]
fn walk_plain_named_symlink_to_archive_target_is_refused() {
    // Adversarial: the link NAME is a harmless `.txt`, but its RESOLVED TARGET
    // is a `.har` container. The audit classifies by target extension too, so
    // expanding the archive is still refused. The refusal message uses the
    // link's own (`.txt`) extension => the GENERIC wording, naming the link.
    let root_dir = tempfile::tempdir().unwrap();
    let outside_dir = tempfile::tempdir().unwrap();
    let har_target = outside_dir.path().join("exfil.har");
    fs::write(&har_target, "har_target_body\n").unwrap();
    symlink(&har_target, root_dir.path().join("innocent.txt")).unwrap();

    let (_chunks, errors) = drain(&FilesystemSource::new(root_dir.path().to_path_buf()));
    let joined = error_strings(&errors);
    let refusal = joined
        .iter()
        .find(|m| {
            m.contains("archive symlink expansion is blocked to prevent link-swap exfiltration")
        })
        .unwrap_or_else(|| {
            panic!("a plain-named link to an archive target must be refused; got {joined:?}")
        });
    assert!(
        refusal.contains("innocent.txt"),
        "the target-based refusal must name the link innocent.txt, got: {refusal}"
    );
}

#[test]
fn walk_archive_named_symlink_to_plain_target_refused_by_name_and_sibling_scanned() {
    // The link NAME is `.zip` but its target is a plain in-tree `.txt`. The
    // audit refuses by LINK NAME (never opens the target to check), and the
    // real sibling that the link points at is still scanned exactly once via
    // its own path — proving the refusal is name-based and does not suppress
    // the genuine file.
    let root_dir = tempfile::tempdir().unwrap();
    let real = root_dir.path().join("real.txt");
    fs::write(&real, "archive_named_link_plain_target_marker\n").unwrap();
    symlink(&real, root_dir.path().join("bait.zip")).unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root_dir.path().to_path_buf()));
    let joined = error_strings(&errors);
    let refusal = joined
        .iter()
        .find(|m| {
            m.contains("archive symlink expansion is blocked to prevent link-swap exfiltration")
        })
        .unwrap_or_else(|| panic!("an archive-named link must be refused by name; got {joined:?}"));
    assert!(
        refusal.contains("bait.zip"),
        "the name-based refusal must name bait.zip, got: {refusal}"
    );
    assert_eq!(
        files_containing(&chunks, "archive_named_link_plain_target_marker"),
        1,
        "the real target file is scanned exactly once via its own path, not through the refused link"
    );
}

#[test]
fn walk_dangling_archive_symlink_is_still_refused_by_name() {
    // Fail-closed: a `.zip` symlink whose target NEVER existed cannot be
    // classified by target, so the audit refuses it by link name rather than
    // silently dropping it (a silent drop would read as "clean").
    let root_dir = tempfile::tempdir().unwrap();
    symlink(
        root_dir.path().join("nonexistent_target_xyz"),
        root_dir.path().join("broken.zip"),
    )
    .unwrap();

    let (_chunks, errors) = drain(&FilesystemSource::new(root_dir.path().to_path_buf()));
    let joined = error_strings(&errors);
    let refusal = joined
        .iter()
        .find(|m| {
            m.contains("archive symlink expansion is blocked to prevent link-swap exfiltration")
        })
        .unwrap_or_else(|| {
            panic!(
                "a dangling archive symlink must be refused by name, not dropped; got {joined:?}"
            )
        });
    assert!(
        refusal.contains("broken.zip"),
        "the dangling-link refusal must name broken.zip, got: {refusal}"
    );
}

// ---------------------------------------------------------------------------
// --include asymmetry: plain-file link READ; expandable link REFUSED
// ---------------------------------------------------------------------------

#[test]
fn include_symlink_to_plain_file_is_canonicalized_then_read() {
    // The documented `--include` asymmetry: a symlink to a PLAIN file that the
    // user EXPLICITLY named is canonicalized to its real target and read (the
    // real path is opened, so `O_NOFOLLOW` sees a regular file, not a link).
    // Content is scanned exactly once.
    let root_dir = tempfile::tempdir().unwrap();
    let real = root_dir.path().join("real_secret.txt");
    fs::write(&real, "included_plain_symlink_read_marker_42\n").unwrap();
    let link = root_dir.path().join("alias.txt");
    symlink(&real, &link).unwrap();

    let src =
        FilesystemSource::new(root_dir.path().to_path_buf()).with_include_paths(vec![link.clone()]);
    let (chunks, errors) = drain(&src);
    assert_eq!(
        generic_archive_refusals(&errors),
        0,
        "an --include of a plain-file symlink must NOT raise an archive refusal: {errors:?}"
    );
    assert_eq!(
        files_containing(&chunks, "included_plain_symlink_read_marker_42"),
        1,
        "an explicitly --include'd plain-file symlink is canonicalize-then-read exactly once"
    );
}

#[test]
fn include_archive_symlink_is_refused_loudly() {
    // The mirror of the read case: an `--include`d symlink whose link name is
    // an expandable archive (`.zip`) pointing at an out-of-tree target is
    // REFUSED with the include-specific wording, naming the link path.
    let root_dir = tempfile::tempdir().unwrap();
    let outside_dir = tempfile::tempdir().unwrap();
    let target = outside_dir.path().join("victim_payload");
    fs::write(&target, "victim_body\n").unwrap();
    let link = root_dir.path().join("creds.zip");
    symlink(&target, &link).unwrap();

    let src =
        FilesystemSource::new(root_dir.path().to_path_buf()).with_include_paths(vec![link.clone()]);
    let (chunks, errors) = drain(&src);
    let joined = error_strings(&errors);
    let refusal = joined
        .iter()
        .find(|m| {
            m.contains("refusing to scan explicitly included archive symlink")
                && m.contains(
                    "archive symlink expansion is blocked to prevent link-swap exfiltration",
                )
        })
        .unwrap_or_else(|| {
            panic!("an --include of an archive symlink must be refused loudly; got {joined:?}")
        });
    assert!(
        refusal.contains("creds.zip"),
        "the include refusal must name the link creds.zip, got: {refusal}"
    );
    assert_eq!(
        files_containing(&chunks, "victim_body"),
        0,
        "the out-of-tree archive-link target must never be scanned via --include"
    );
}

#[test]
fn include_plain_named_symlink_to_archive_target_is_refused() {
    // Adversarial `--include`: link NAME is a harmless `.txt` but the RESOLVED
    // target is an expandable `.har`. The include branch classifies by the
    // canonicalized target too, so it is refused — a plain link name cannot
    // smuggle an archive-expansion of an off-tree target.
    let root_dir = tempfile::tempdir().unwrap();
    let outside_dir = tempfile::tempdir().unwrap();
    let har_target = outside_dir.path().join("capture.har");
    fs::write(&har_target, "har_capture_body\n").unwrap();
    let link = root_dir.path().join("notes.txt");
    symlink(&har_target, &link).unwrap();

    let src =
        FilesystemSource::new(root_dir.path().to_path_buf()).with_include_paths(vec![link.clone()]);
    let (chunks, errors) = drain(&src);
    let joined = error_strings(&errors);
    let refusal = joined
        .iter()
        .find(|m| {
            m.contains("refusing to scan explicitly included archive symlink")
                && m.contains(
                    "archive symlink expansion is blocked to prevent link-swap exfiltration",
                )
        })
        .unwrap_or_else(|| {
            panic!(
                "a plain-named include link to an archive target must be refused; got {joined:?}"
            )
        });
    assert!(
        refusal.contains("notes.txt"),
        "the include refusal must name the link notes.txt, got: {refusal}"
    );
    assert_eq!(
        files_containing(&chunks, "har_capture_body"),
        0,
        "the off-tree archive target must never be scanned via a plain-named include link"
    );
}

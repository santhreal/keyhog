//! Regression + contract: scanning a Git-LFS *pointer* file must record a
//! `git_lfs_pointer` partial-coverage gap. A pointer is the tiny text stand-in
//! Git LFS commits in place of a large blob; the real blob lives in LFS storage
//! and is not on disk unless `git lfs pull` has materialised it. Reporting an
//! unmaterialised-pointer repo as clean is a false-clean (Law 10): the blob can
//! hold a keystore, `.pem`, or encrypted `.env` that was never scanned.
//!
//! Two production paths reach a pointer and both are locked here:
//!   * text/unknown-extension pointers (`creds.txt`, no extension) take the
//!     small-file single-chunk path, where the whole content is already in hand
//!     — detection there is zero extra I/O and the pointer text is still scanned.
//!   * skip-extension pointers (`logo.png`, `model.bin`) — the common real case,
//!     since Git LFS keeps the asset's binary extension — are normally dropped
//!     unread as binary; a bounded, size-gated prefix probe recognises the
//!     pointer so it is attributed precisely instead of counted as plain binary.
//!
//! Recognition itself (`keyhog_core::git_lfs::is_git_lfs_pointer`) is locked in
//! the core crate; these tests lock the *source-side coverage accounting*.

use keyhog_core::Source;
use keyhog_sources::{reset_skipped_over_max_size, skip_counts, FilesystemSource, SkipCounts};
use std::sync::{Mutex, MutexGuard};

mod support;

/// The skip counters are process-global atomics. This integration binary runs
/// every test below in the same process, so counter-mutating tests serialise on
/// one lock: each holds it across reset → scan → read so a concurrent scan can
/// never inflate another test's delta.
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn counter_guard() -> MutexGuard<'static, ()> {
    COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

const OID_64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const VERSION_LINE: &str = "version https://git-lfs.github.com/spec/v1";

fn canonical_pointer() -> String {
    format!("{VERSION_LINE}\noid sha256:{OID_64}\nsize 1024\n")
}

/// Write one file into a fresh tree, drive the real filesystem scan, and return
/// the end-of-scan counters plus the text of every emitted chunk. The caller
/// holds `counter_guard()` and has reset the counters, so the returned snapshot
/// reflects exactly this scan.
fn scan_one_file(name: &str, content: &[u8]) -> (SkipCounts, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(name), content).expect("write fixture file");
    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, _errors) = support::split_chunk_results(&rows);
    let texts: Vec<String> = chunks
        .iter()
        .map(|chunk| chunk.data.as_ref().to_string())
        .collect();
    (skip_counts(), texts)
}

// ── text/unknown-extension path (small-file single chunk) ────────────────────

#[test]
fn txt_canonical_pointer_records_one_git_lfs_pointer_gap() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let (counts, _texts) = scan_one_file("creds.txt", canonical_pointer().as_bytes());
    assert_eq!(
        counts.git_lfs_pointer, 1,
        "a canonical .txt pointer must record exactly one git_lfs_pointer coverage gap"
    );
}

#[test]
fn txt_pointer_text_is_still_scanned_additively() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let (counts, texts) = scan_one_file("creds.txt", canonical_pointer().as_bytes());
    assert_eq!(counts.git_lfs_pointer, 1);
    assert!(
        texts.iter().any(|text| text.contains("git-lfs.github.com")),
        "the pointer text must still be emitted as a chunk (detection is additive), got {texts:?}"
    );
}

#[test]
fn txt_pointer_is_not_counted_as_a_file_skip() {
    // `git_lfs_pointer` is a PARTIAL-coverage note, not a whole-file skip: the
    // pointer file itself IS scanned. So it must live outside SkipCounts::total()
    // (the file-skip total), exactly like structured_source_parse_failures.
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let (counts, _texts) = scan_one_file("creds.txt", canonical_pointer().as_bytes());
    assert_eq!(counts.git_lfs_pointer, 1);
    assert_eq!(
        counts.total(),
        0,
        "a scanned pointer file must not inflate the file-skip total; git_lfs_pointer is partial coverage"
    );
}

#[test]
fn txt_crlf_pointer_is_recognised() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let content = format!("{VERSION_LINE}\r\noid sha256:{OID_64}\r\nsize 7\r\n");
    let (counts, _texts) = scan_one_file("creds.txt", content.as_bytes());
    assert_eq!(
        counts.git_lfs_pointer, 1,
        "CRLF line endings must still count"
    );
}

#[test]
fn txt_pointer_without_trailing_newline_is_recognised() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let content = format!("{VERSION_LINE}\noid sha256:{OID_64}\nsize 42");
    let (counts, _texts) = scan_one_file("creds.txt", content.as_bytes());
    assert_eq!(counts.git_lfs_pointer, 1);
}

#[test]
fn txt_pointer_with_ext_line_is_recognised() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let content =
        format!("{VERSION_LINE}\next-0-shake256 sha256:{OID_64}\noid sha256:{OID_64}\nsize 9\n");
    let (counts, _texts) = scan_one_file("creds.txt", content.as_bytes());
    assert_eq!(
        counts.git_lfs_pointer, 1,
        "an ext-* line before oid must not break recognition"
    );
}

#[test]
fn txt_uppercase_version_line_is_recognised() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let content =
        format!("VERSION HTTPS://GIT-LFS.GITHUB.COM/SPEC/V1\noid sha256:{OID_64}\nsize 3\n");
    let (counts, _texts) = scan_one_file("creds.txt", content.as_bytes());
    assert_eq!(
        counts.git_lfs_pointer, 1,
        "the version line match is case-insensitive"
    );
}

#[test]
fn txt_pointer_with_extra_secret_line_is_counted_and_the_secret_is_scanned() {
    // A pointer file with an unexpected extra line is still a pointer (the parser
    // stops after version→oid→size), and because the text path scans the whole
    // file, a real secret sitting on that extra line is NOT lost.
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let content = format!(
        "{}extra_line_marker=KEYHOG_LFS_EXTRA_LINE\n",
        canonical_pointer()
    );
    let (counts, texts) = scan_one_file("creds.txt", content.as_bytes());
    assert_eq!(counts.git_lfs_pointer, 1);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("KEYHOG_LFS_EXTRA_LINE")),
        "a secret on an extra line of a pointer file must still be scanned, got {texts:?}"
    );
}

// ── skip-extension path (the common real case: binary-named pointers) ─────────

#[test]
fn png_canonical_pointer_records_git_lfs_pointer_gap() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let (counts, _texts) = scan_one_file("logo.png", canonical_pointer().as_bytes());
    assert_eq!(
        counts.git_lfs_pointer, 1,
        "a .png whose content is a pointer must be recognised, not dropped as binary"
    );
}

#[test]
fn png_pointer_is_not_counted_as_binary() {
    // The precision win: a binary-named pointer is attributed to git_lfs_pointer
    // (with its `git lfs pull` remedy), NOT lumped into the generic binary skip.
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let (counts, _texts) = scan_one_file("logo.png", canonical_pointer().as_bytes());
    assert_eq!(counts.git_lfs_pointer, 1);
    assert_eq!(
        counts.binary, 0,
        "a .png pointer must NOT be mis-attributed to the binary skip counter"
    );
}

#[test]
fn bin_canonical_pointer_records_git_lfs_pointer_gap() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let (counts, _texts) = scan_one_file("model.bin", canonical_pointer().as_bytes());
    assert_eq!(counts.git_lfs_pointer, 1);
}

#[test]
fn png_real_small_binary_asset_is_counted_binary_not_pointer() {
    // A genuine small PNG (magic-prefixed, not a pointer) must fail the pointer
    // probe and fall through to the normal binary skip — no false positive.
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let mut content = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
    content.extend_from_slice(&[0u8; 64]);
    let (counts, _texts) = scan_one_file("icon.png", &content);
    assert_eq!(
        counts.git_lfs_pointer, 0,
        "a real PNG must not be seen as a pointer"
    );
    assert_eq!(counts.binary, 1, "a real PNG is a normal binary skip");
}

#[test]
fn png_large_asset_is_not_probed_and_counts_binary() {
    // A .png larger than one pointer is a real asset: the size gate skips the
    // probe entirely (Law 7 — no whole-content read on a large binary), and it is
    // recorded as an ordinary binary skip.
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let mut content = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
    content.extend_from_slice(&vec![0x42u8; 4096]);
    let (counts, _texts) = scan_one_file("photo.png", &content);
    assert_eq!(counts.git_lfs_pointer, 0);
    assert_eq!(
        counts.binary, 1,
        "a large .png asset is an ordinary binary skip, not probed"
    );
}

// ── negatives (not a pointer → no gap, file still handled normally) ───────────

#[test]
fn plain_text_file_records_no_git_lfs_pointer_gap() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let (counts, _texts) =
        scan_one_file("notes.txt", b"just some ordinary notes\nnothing special\n");
    assert_eq!(counts.git_lfs_pointer, 0);
}

#[test]
fn prose_mentioning_git_lfs_records_no_gap() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let content = b"# git-lfs stores large binaries out of band\nsee the docs for details\n";
    let (counts, _texts) = scan_one_file("README.txt", content);
    assert_eq!(
        counts.git_lfs_pointer, 0,
        "prose about git-lfs is not a pointer"
    );
}

#[test]
fn missing_version_line_records_no_gap() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let content = format!("oid sha256:{OID_64}\nsize 1024\n");
    let (counts, _texts) = scan_one_file("creds.txt", content.as_bytes());
    assert_eq!(
        counts.git_lfs_pointer, 0,
        "a pointer without the version line is not a pointer"
    );
}

#[test]
fn missing_oid_line_records_no_gap() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let content = format!("{VERSION_LINE}\nsize 1024\n");
    let (counts, _texts) = scan_one_file("creds.txt", content.as_bytes());
    assert_eq!(counts.git_lfs_pointer, 0);
}

#[test]
fn out_of_order_size_before_oid_records_no_gap() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let content = format!("{VERSION_LINE}\nsize 1024\noid sha256:{OID_64}\n");
    let (counts, _texts) = scan_one_file("creds.txt", content.as_bytes());
    assert_eq!(
        counts.git_lfs_pointer, 0,
        "line order is significant: size must follow oid"
    );
}

#[test]
fn empty_file_records_no_gap() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let (counts, _texts) = scan_one_file("empty.txt", b"");
    assert_eq!(counts.git_lfs_pointer, 0);
}

// ── Law-7 size bound ─────────────────────────────────────────────────────────

#[test]
fn oversized_pointer_text_is_not_counted_but_is_still_scanned() {
    // A "pointer" whose content exceeds one pointer's worth of bytes is not a
    // real pointer (they are ~130 bytes). The size gate skips the whole-content
    // check so a large text file never pays the pointer scan — yet the file is
    // still scanned normally.
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let mut content = canonical_pointer();
    content.push('\n');
    content.push_str(&"#".repeat(1100)); // pushes total well past 1024 bytes
    let (counts, texts) = scan_one_file("creds.txt", content.as_bytes());
    assert_eq!(
        counts.git_lfs_pointer, 0,
        "content larger than one pointer must not be probed as a pointer (Law 7 bound)"
    );
    assert!(
        !texts.is_empty(),
        "the oversized file is still scanned as ordinary text"
    );
}

#[test]
fn pointer_at_the_size_bound_is_counted() {
    // Boundary: content length exactly at the cap (1024) is still probed. Pad a
    // valid pointer with trailing filler (ignored after the size line) to hit it.
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let mut content = canonical_pointer();
    content.push('\n');
    let pad = 1024 - content.len();
    content.push_str(&"#".repeat(pad));
    assert_eq!(content.len(), 1024, "fixture must sit exactly on the cap");
    let (counts, _texts) = scan_one_file("creds.txt", content.as_bytes());
    assert_eq!(
        counts.git_lfs_pointer, 1,
        "a pointer whose content length equals the cap is still recognised"
    );
}

// ── accounting sanity ────────────────────────────────────────────────────────

#[test]
fn two_pointer_files_record_two_gaps() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), canonical_pointer()).expect("write a");
    std::fs::write(dir.path().join("logo.png"), canonical_pointer()).expect("write b");
    let _rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    assert_eq!(
        skip_counts().git_lfs_pointer,
        2,
        "one text-path pointer + one skip-extension pointer must record two gaps"
    );
}

#[test]
fn reset_clears_the_git_lfs_pointer_counter() {
    let _guard = counter_guard();
    reset_skipped_over_max_size();
    let (counts, _texts) = scan_one_file("creds.txt", canonical_pointer().as_bytes());
    assert_eq!(counts.git_lfs_pointer, 1);
    reset_skipped_over_max_size();
    assert_eq!(
        skip_counts().git_lfs_pointer,
        0,
        "reset must zero the git_lfs_pointer counter alongside every other skip counter"
    );
}

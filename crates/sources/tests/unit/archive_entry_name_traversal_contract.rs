//! Security contract for `validate_scan_archive_entry_name` (reached via the
//! `SourceTestApi` facade), the guard every archive extractor (zip / 7z / rar)
//! runs over each entry name before the entry is processed.
//!
//! keyhog scans archive members in memory rather than extracting them to disk,
//! but the entry name still flows into the finding's displayed path, so a
//! traversal / absolute name is refused (and the entry skip-counted) rather than
//! trusted. The guard is layered: it rejects empty / NUL / backslash names, the
//! textual `../` family and Windows drive-absolute prefixes, and any `..` /
//! root / prefix path component, and it does so AT EVERY percent-decoding layer
//! (up to 10), so `%2e%2e/` and double-encoded `%252e%252e%252f` cannot smuggle
//! a `../` past a single decode. These tests pin the exact refusal reason for
//! each class and pin that ordinary relative names (including the non-traversal
//! lookalikes `..env`, `foo..`, `./foo`) are accepted, over-rejection here
//! would silently drop a real archived secret from the scan.

use keyhog_sources::testing::{SourceTestApi, TestApi};

fn validate(name: &str) -> Result<(), String> {
    TestApi.validate_archive_entry_name(name)
}

fn reason(name: &str) -> String {
    validate(name).expect_err("expected the entry name to be refused")
}

// ── accepted: ordinary relative entry names ─────────────────────────────────

#[test]
fn plain_filename_is_accepted() {
    assert!(validate("config.env").is_ok());
}

#[test]
fn nested_relative_path_is_accepted() {
    assert!(validate("src/main/resources/application.yaml").is_ok());
}

#[test]
fn deeply_nested_path_is_accepted() {
    assert!(validate("a/b/c/d/e/f/secret.txt").is_ok());
}

#[test]
fn dotfile_is_accepted() {
    assert!(validate(".env").is_ok());
}

#[test]
fn multi_extension_filename_is_accepted() {
    assert!(validate("archive.tar.gz").is_ok());
}

// ── accepted: non-traversal `..` lookalikes (over-rejection = lost secret) ───

#[test]
fn leading_double_dot_in_a_filename_is_accepted() {
    // "..env" is a filename that begins with two dots, NOT a parent reference.
    assert!(validate("..env").is_ok());
}

#[test]
fn trailing_double_dot_in_a_filename_is_accepted() {
    // "foo.." has no path separator before the dots (a normal component).
    assert!(validate("foo..").is_ok());
    assert!(validate("foo..bar/baz").is_ok());
}

#[test]
fn current_dir_prefix_is_accepted() {
    // "./foo" is a CurDir component, which is harmless (not Root/Parent/Prefix).
    assert!(validate("./foo").is_ok());
}

#[test]
fn percent_encoded_space_in_name_is_accepted() {
    // "%20" decodes to a space; the decoded "file name.txt" is still a safe
    // relative name, so it survives the decode-revalidate loop.
    assert!(validate("file%20name.txt").is_ok());
}

#[test]
fn lone_percent_literal_is_accepted() {
    // "%25" decodes to "%", a stable safe single-character name.
    assert!(validate("%25").is_ok());
}

// ── refused: textual parent traversal ───────────────────────────────────────

#[test]
fn leading_parent_traversal_is_refused() {
    assert_eq!(reason("../etc/passwd"), "path traversal in entry name");
}

#[test]
fn mid_path_parent_traversal_is_refused() {
    assert_eq!(
        reason("pkg/../../etc/shadow"),
        "path traversal in entry name"
    );
}

#[test]
fn trailing_parent_traversal_is_refused() {
    assert_eq!(reason("pkg/.."), "path traversal in entry name");
}

#[test]
fn bare_double_dot_is_refused() {
    assert_eq!(reason(".."), "path traversal in entry name");
}

#[test]
fn collapsing_dot_run_traversal_is_refused() {
    // "....//" contains the substring "../" and must not slip through.
    assert_eq!(reason("....//etc/passwd"), "path traversal in entry name");
}

// ── refused: percent-encoded traversal at every decoding layer ──────────────

#[test]
fn single_encoded_dot_traversal_is_refused() {
    // "%2e%2e/" -> "../" after one decode; the loop revalidates the decoded form.
    assert_eq!(reason("%2e%2e/etc"), "path traversal in entry name");
}

#[test]
fn encoded_slash_traversal_is_refused() {
    assert_eq!(reason("..%2fetc/passwd"), "path traversal in entry name");
}

#[test]
fn double_encoded_traversal_is_refused() {
    // "%252e%252e%252f" -> "%2e%2e%2f" -> "../" across two decode layers.
    assert_eq!(reason("%252e%252e%252f"), "path traversal in entry name");
}

#[test]
fn fully_encoded_parent_pair_is_refused() {
    assert_eq!(reason("%2e%2e%2f%2e%2e"), "path traversal in entry name");
}

// ── refused: absolute paths ─────────────────────────────────────────────────

#[test]
fn unix_absolute_path_is_refused() {
    assert_eq!(
        reason("/etc/passwd"),
        "absolute or parent path component in entry name"
    );
}

#[test]
fn windows_drive_absolute_is_refused() {
    assert_eq!(
        reason("C:/Windows/System32"),
        "path traversal in entry name"
    );
}

#[test]
fn windows_drive_absolute_lowercase_is_refused() {
    assert_eq!(reason("d:/temp/x"), "path traversal in entry name");
}

// ── refused: structural / encoding hazards ──────────────────────────────────

#[test]
fn backslash_in_name_is_refused() {
    // Backslash is rejected outright so a Windows-style "..\\..\\" cannot evade
    // the forward-slash traversal checks.
    assert_eq!(reason("..\\..\\windows"), "backslash in entry name");
    assert_eq!(reason("dir\\file"), "backslash in entry name");
}

#[test]
fn nul_byte_in_name_is_refused() {
    assert_eq!(reason("foo\0bar"), "nul byte in entry name");
}

#[test]
fn empty_name_is_refused() {
    assert_eq!(reason(""), "empty entry name");
}

#[test]
fn excessively_percent_encoded_name_is_refused() {
    // A name that keeps changing for more than 10 decode layers is rejected
    // rather than decoded unboundedly.
    let onion = format!("%{}", "25".repeat(15));
    assert_eq!(
        reason(&onion),
        "path contains excessively encoded percent sequences"
    );
}

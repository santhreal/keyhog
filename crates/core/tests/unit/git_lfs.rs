//! Lock the shared Git-LFS pointer recognition (`keyhog_core::git_lfs`), which
//! both the scanner (oid suppression) and sources (unscanned-blob coverage gap)
//! depend on. Recognition is strict: a false positive would suppress a real
//! credential, so the negative and adversarial cases matter as much as the
//! positives.

use keyhog_core::git_lfs::{
    is_git_lfs_oid_line, is_git_lfs_pointer, is_git_lfs_size_line, is_git_lfs_version_line,
    GIT_LFS_VERSION_LINE,
};

const OID_64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn canonical() -> String {
    format!("{GIT_LFS_VERSION_LINE}\noid sha256:{OID_64}\nsize 1024\n")
}

// ── whole-pointer recognition (positive) ─────────────────────────────────────

#[test]
fn canonical_pointer_is_recognised() {
    assert!(is_git_lfs_pointer(canonical().as_bytes()));
}

#[test]
fn pointer_without_trailing_newline_is_recognised() {
    let text = format!("{GIT_LFS_VERSION_LINE}\noid sha256:{OID_64}\nsize 42");
    assert!(is_git_lfs_pointer(text.as_bytes()));
}

#[test]
fn pointer_with_crlf_line_endings_is_recognised() {
    let text = format!("{GIT_LFS_VERSION_LINE}\r\noid sha256:{OID_64}\r\nsize 7\r\n");
    assert!(is_git_lfs_pointer(text.as_bytes()));
}

#[test]
fn pointer_with_ext_line_between_version_and_oid_is_recognised() {
    // `ext-*` sorts before `oid` alphabetically, so it appears between the
    // version line and the oid line in a real pointer.
    let text = format!(
        "{GIT_LFS_VERSION_LINE}\next-0-shake256 sha256:{OID_64}\noid sha256:{OID_64}\nsize 9\n"
    );
    assert!(is_git_lfs_pointer(text.as_bytes()));
}

#[test]
fn version_line_case_insensitive() {
    let text = format!("VERSION HTTPS://GIT-LFS.GITHUB.COM/SPEC/V1\noid sha256:{OID_64}\nsize 3\n");
    assert!(is_git_lfs_pointer(text.as_bytes()));
}

#[test]
fn large_size_value_is_recognised() {
    let text = format!("{GIT_LFS_VERSION_LINE}\noid sha256:{OID_64}\nsize 9999999999\n");
    assert!(is_git_lfs_pointer(text.as_bytes()));
}

// ── whole-pointer recognition (negative) ─────────────────────────────────────

#[test]
fn empty_content_is_not_a_pointer() {
    assert!(!is_git_lfs_pointer(b""));
}

#[test]
fn missing_version_line_is_not_a_pointer() {
    let text = format!("oid sha256:{OID_64}\nsize 1024\n");
    assert!(!is_git_lfs_pointer(text.as_bytes()));
}

#[test]
fn missing_oid_line_is_not_a_pointer() {
    let text = format!("{GIT_LFS_VERSION_LINE}\nsize 1024\n");
    assert!(!is_git_lfs_pointer(text.as_bytes()));
}

#[test]
fn missing_size_line_is_not_a_pointer() {
    let text = format!("{GIT_LFS_VERSION_LINE}\noid sha256:{OID_64}\n");
    assert!(!is_git_lfs_pointer(text.as_bytes()));
}

#[test]
fn size_before_oid_out_of_order_is_not_a_pointer() {
    let text = format!("{GIT_LFS_VERSION_LINE}\nsize 1024\noid sha256:{OID_64}\n");
    assert!(!is_git_lfs_pointer(text.as_bytes()));
}

#[test]
fn plain_prose_mentioning_lfs_is_not_a_pointer() {
    assert!(!is_git_lfs_pointer(
        b"# git-lfs stores large binaries out of band\nsome text\n"
    ));
}

// ── oid line ─────────────────────────────────────────────────────────────────

#[test]
fn oid_line_requires_exactly_64_hex() {
    assert!(is_git_lfs_oid_line(
        format!("oid sha256:{OID_64}").as_bytes()
    ));
}

#[test]
fn oid_line_rejects_63_hex() {
    let short = &OID_64[..63];
    assert!(!is_git_lfs_oid_line(
        format!("oid sha256:{short}").as_bytes()
    ));
}

#[test]
fn oid_line_rejects_65_hex() {
    let long = format!("{OID_64}0");
    assert!(!is_git_lfs_oid_line(
        format!("oid sha256:{long}").as_bytes()
    ));
}

#[test]
fn oid_line_rejects_non_hex_body() {
    // A valid-shaped provider token on an oid line is NOT a git-LFS oid, so the
    // scanner must still surface it (recall-correct suppression).
    let value = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ";
    assert!(!is_git_lfs_oid_line(
        format!("oid sha256:{value}").as_bytes()
    ));
}

#[test]
fn oid_line_rejects_wrong_algorithm() {
    assert!(!is_git_lfs_oid_line(
        format!("oid sha512:{OID_64}").as_bytes()
    ));
}

#[test]
fn oid_line_tolerates_surrounding_whitespace() {
    assert!(is_git_lfs_oid_line(
        format!("  oid sha256:{OID_64}  ").as_bytes()
    ));
}

// ── size line ────────────────────────────────────────────────────────────────

#[test]
fn size_line_accepts_decimal() {
    assert!(is_git_lfs_size_line(b"size 12345"));
}

#[test]
fn size_line_rejects_empty_value() {
    assert!(!is_git_lfs_size_line(b"size "));
}

#[test]
fn size_line_rejects_non_digit_value() {
    assert!(!is_git_lfs_size_line(b"size 12ab"));
}

// ── version line ─────────────────────────────────────────────────────────────

#[test]
fn version_line_rejects_other_url() {
    assert!(!is_git_lfs_version_line(
        b"version https://example.com/spec/v1"
    ));
}

#[test]
fn version_line_tolerates_surrounding_whitespace() {
    assert!(is_git_lfs_version_line(
        format!("  {GIT_LFS_VERSION_LINE}  ").as_bytes()
    ));
}

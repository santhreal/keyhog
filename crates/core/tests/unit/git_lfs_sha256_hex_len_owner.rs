//! Migrated from `src/git_lfs.rs` inline tests (KH-GAP-004).
//!
//! `SHA256_HEX_LEN` is the single crate-wide owner for "a sha256 digest is 64
//! lowercase hex characters". These tests lock the constant's value AND tie it
//! to the observable `is_git_lfs_oid_line` boundary, so a drift in the owner
//! would surface as both a value mismatch and a recognition-boundary change.

use keyhog_core::git_lfs::{is_git_lfs_oid_line, SHA256_HEX_LEN};

#[test]
fn sha256_hex_len_is_sixty_four() {
    assert_eq!(SHA256_HEX_LEN, 64);
}

#[test]
fn oid_line_accepts_exactly_sha256_hex_len_hex() {
    let line = format!("oid sha256:{}", "a".repeat(SHA256_HEX_LEN));
    assert!(
        is_git_lfs_oid_line(line.as_bytes()),
        "an oid line with exactly SHA256_HEX_LEN (64) hex must be recognised"
    );
}

#[test]
fn oid_line_rejects_one_hex_short_of_owner() {
    let line = format!("oid sha256:{}", "a".repeat(SHA256_HEX_LEN - 1));
    assert!(
        !is_git_lfs_oid_line(line.as_bytes()),
        "63 hex (SHA256_HEX_LEN - 1) is not a valid oid body"
    );
}

#[test]
fn oid_line_rejects_one_hex_over_owner() {
    let line = format!("oid sha256:{}", "a".repeat(SHA256_HEX_LEN + 1));
    assert!(
        !is_git_lfs_oid_line(line.as_bytes()),
        "65 hex (SHA256_HEX_LEN + 1) is not a valid oid body"
    );
}

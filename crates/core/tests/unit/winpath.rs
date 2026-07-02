//! KH-GAP-004 (core slice): Windows-path classification predicates are tested
//! here in `tests/unit/`, not inline in `src/winpath.rs`. Covers the two
//! DISTINCT same-name-divergence-safe predicates: the BROAD
//! `has_windows_drive_prefix` (any `X:` prefix, incl. drive-relative `C:evil`)
//! and the STRICT `is_windows_absolute` (only root-anchored `C:\dir` / `C:/dir`).
use keyhog_core::winpath::{has_windows_drive_prefix, is_windows_absolute};

#[test]
fn drive_prefix_accepts_bare_drive() {
    assert!(has_windows_drive_prefix("C:"));
}

#[test]
fn drive_prefix_accepts_drive_relative() {
    assert!(has_windows_drive_prefix("C:evil"));
}

#[test]
fn drive_prefix_accepts_backslash_absolute() {
    assert!(has_windows_drive_prefix("C:\\Windows\\System32"));
}

#[test]
fn drive_prefix_accepts_forward_slash_absolute() {
    assert!(has_windows_drive_prefix("D:/data"));
}

#[test]
fn drive_prefix_accepts_lowercase_drive() {
    assert!(has_windows_drive_prefix("z:file"));
}

#[test]
fn drive_prefix_rejects_relative() {
    assert!(!has_windows_drive_prefix("relative/path"));
}

#[test]
fn drive_prefix_rejects_unix_absolute() {
    assert!(!has_windows_drive_prefix("/etc/passwd"));
}

#[test]
fn drive_prefix_rejects_leading_digit() {
    assert!(!has_windows_drive_prefix("1:oops"));
}

#[test]
fn drive_prefix_rejects_single_letter() {
    assert!(!has_windows_drive_prefix("C"));
}

#[test]
fn drive_prefix_rejects_empty() {
    assert!(!has_windows_drive_prefix(""));
}

#[test]
fn drive_prefix_rejects_colon_first() {
    assert!(!has_windows_drive_prefix(":C"));
}

#[test]
fn absolute_accepts_backslash() {
    assert!(is_windows_absolute("C:\\Windows"));
}

#[test]
fn absolute_accepts_forward_slash() {
    assert!(is_windows_absolute("C:/Users/me"));
}

#[test]
fn absolute_accepts_lowercase_drive() {
    assert!(is_windows_absolute("d:/data"));
}

#[test]
fn absolute_rejects_bare_drive() {
    assert!(!is_windows_absolute("C:"));
}

#[test]
fn absolute_rejects_drive_relative() {
    // The key divergence: drive-relative is a drive PREFIX but NOT absolute.
    assert!(!is_windows_absolute("C:evil"));
    assert!(has_windows_drive_prefix("C:evil"));
}

#[test]
fn absolute_rejects_unix_absolute() {
    assert!(!is_windows_absolute("/etc/passwd"));
}

#[test]
fn absolute_rejects_relative() {
    assert!(!is_windows_absolute("dir/file"));
}

#[test]
fn absolute_rejects_leading_digit() {
    assert!(!is_windows_absolute("1:/oops"));
}

#[test]
fn absolute_rejects_empty() {
    assert!(!is_windows_absolute(""));
}

#[test]
fn absolute_rejects_wrong_third_char() {
    assert!(!is_windows_absolute("C:x"));
}

#[test]
fn strict_implies_prefix() {
    // Every strictly-absolute path is also drive-prefixed (the strict set is
    // a subset of the broad set); the reverse does not hold.
    for p in ["C:/a", "C:\\a", "z:/x"] {
        assert!(is_windows_absolute(p));
        assert!(has_windows_drive_prefix(p));
    }
}

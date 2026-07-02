//! Canonical Windows-path classification predicates.
//!
//! ONE PLACE for "does this string carry a Windows drive letter". Two callers
//! previously hand-rolled a private `is_windows_absolute` with *different*
//! semantics under the *same* name — a same-name-divergence trap:
//!
//! * the archive entry-name sanitizer (a security reject) wanted the BROAD
//!   sense: reject anything drive-letter-prefixed, including the drive-RELATIVE
//!   `C:evil` form, because on Windows `C:evil` still escapes the intended
//!   extraction root; and
//! * the SARIF URI formatter wanted the STRICT sense: only a fully-qualified
//!   absolute path `C:\dir` / `C:/dir` is "absolute"; the drive-relative
//!   `C:rel` resolves against the drive's current directory and is NOT absolute.
//!
//! Both are correct for their caller, so they are two DISTINCT predicates with
//! DISTINCT names, defined once here and imported where needed. No reader has to
//! guess which `is_windows_absolute` a call meant.

/// True iff `s` begins with a Windows drive-letter prefix (`X:`), regardless of
/// whether a path separator follows. This is the BROAD, security-oriented sense
/// used to reject untrusted archive entry names: it catches the fully-qualified
/// `C:\evil` *and* the drive-relative `C:evil`, both of which can escape an
/// intended extraction root on Windows.
#[must_use]
pub fn has_windows_drive_prefix(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// True iff `s` is a fully-qualified Windows absolute path: a drive letter, a
/// colon, and a path separator (`C:\dir` or `C:/dir`). This is the STRICT sense
/// used when "absolute" must mean root-anchored — e.g. deciding whether a path
/// is already absolute for URI formatting. The drive-relative `C:rel` is NOT
/// absolute and returns `false`.
#[must_use]
pub fn is_windows_absolute(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'/' || b[2] == b'\\')
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

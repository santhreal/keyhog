//! Canonical Windows-path classification predicates.
//!
//! ONE PLACE for "does this string carry a Windows drive letter". Two callers
//! previously hand-rolled a private `is_windows_absolute` with *different*
//! semantics under the *same* name, a same-name-divergence trap:
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
//!
//! Tests live in `tests/unit/winpath.rs` (KH-GAP-004: no inline test modules
//! in `src/`).

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
/// used when "absolute" must mean root-anchored, e.g. deciding whether a path
/// is already absolute for URI formatting. The drive-relative `C:rel` is NOT
/// absolute and returns `false`.
#[must_use]
pub fn is_windows_absolute(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')
}

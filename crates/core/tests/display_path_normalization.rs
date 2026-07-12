//! Coverage for `strip_windows_verbatim_prefix` (#177) — the allocation-free
//! display normalization that removes the Windows `\\?\` extended-length prefix
//! from operator-facing paths. Previously untested; correctness matters because
//! the same normalized string is what a user reads and what path-keyed output
//! compares.

use keyhog_core::strip_windows_verbatim_prefix as strip;

#[test]
fn strips_the_verbatim_prefix_from_a_drive_path() {
    assert_eq!(strip(r"\\?\C:\Users\me\.env"), r"C:\Users\me\.env");
}

#[test]
fn strips_the_verbatim_prefix_from_a_unc_path() {
    // Documented contract: \\?\UNC\server\share -> UNC\server\share, NOT rebuilt
    // to a leading \\ (allocation-free by design).
    assert_eq!(strip(r"\\?\UNC\server\share"), r"UNC\server\share");
}

#[test]
fn leaves_a_path_without_the_prefix_unchanged() {
    assert_eq!(
        strip("/home/user/.aws/credentials"),
        "/home/user/.aws/credentials"
    );
    assert_eq!(strip(r"C:\plain\path"), r"C:\plain\path");
    assert_eq!(strip(""), "");
}

#[test]
fn requires_the_complete_four_char_prefix() {
    // An incomplete or misshapen prefix must NOT be stripped.
    assert_eq!(strip(r"\\?"), r"\\?"); // missing trailing backslash
    assert_eq!(strip(r"\\"), r"\\");
    assert_eq!(strip(r"\?\x"), r"\?\x"); // wrong shape
}

#[test]
fn strips_exactly_one_prefix_occurrence() {
    // Only the single leading prefix is removed; a doubled prefix keeps the
    // inner one (\\?\ + \\?\x -> \\?\x).
    assert_eq!(strip(r"\\?\\\?\x"), r"\\?\x");
    // The prefix alone normalizes to empty.
    assert_eq!(strip(r"\\?\"), "");
}

#[test]
fn result_is_a_suffix_that_is_identity_or_exactly_the_prefix_removed() {
    // Deterministic property over a spread of shapes: the result is always a
    // tail of the input, no longer than it, and either equals the input or is
    // the input with exactly the 4-char prefix removed.
    for p in [
        r"\\?\C:\a",
        r"\\?\UNC\s\h",
        "/x/y",
        r"D:\z",
        "",
        r"\\?\",
        r"\\?\\\?\q",
        "plain",
        r"\\server\share",
        r"\\?\GLOBALROOT\Device",
    ] {
        let out = strip(p);
        assert!(p.ends_with(out), "{out:?} must be a suffix of {p:?}");
        assert!(out.len() <= p.len());
        assert!(
            out == p || p == format!(r"\\?\{out}"),
            "{p:?} -> {out:?} must be identity or exactly the prefix removed"
        );
    }
}

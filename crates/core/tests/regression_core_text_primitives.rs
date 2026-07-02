//! Regression tests for the core path/case text primitives:
//! `winpath` drive-letter classification, `ascii_ci` case-insensitive
//! affix/substring matching, and `git_lfs` pointer recognition.
//!
//! Every assertion pins a CONCRETE expected boolean so a semantic drift in any
//! primitive (e.g. the `has_windows_drive_prefix` vs `is_windows_absolute`
//! same-name-divergence trap, or ASCII-only case folding leaking into
//! non-ASCII bytes) fails loudly here.

use keyhog_core::ascii_ci::{
    contains_bytes_ignore_ascii_case, contains_ignore_ascii_case, ends_with_ignore_ascii_case,
    starts_with_ignore_ascii_case,
};
use keyhog_core::git_lfs::{
    is_git_lfs_oid_line, is_git_lfs_pointer, is_git_lfs_size_line, is_git_lfs_version_line,
    GIT_LFS_VERSION_LINE,
};
use keyhog_core::winpath::{has_windows_drive_prefix, is_windows_absolute};

// ---------------------------------------------------------------------------
// winpath: the two DISTINCT predicates and their exact divergence.
// ---------------------------------------------------------------------------

/// The load-bearing divergence table. For each input the BROAD predicate
/// (`has_windows_drive_prefix`) and the STRICT predicate (`is_windows_absolute`)
/// must return exactly these booleans. `C:\`/`C:/` are both true/true; the
/// drive-relative `C:relative` is the trap case: prefix=true, absolute=false.
#[test]
fn winpath_divergence_table_exact() {
    // (input, expected has_windows_drive_prefix, expected is_windows_absolute)
    let cases: &[(&str, bool, bool)] = &[
        ("C:\\Windows\\System32", true, true), // backslash absolute
        ("C:/Users/me", true, true),           // forward-slash absolute
        ("C:relative", true, false),           // drive-relative: prefix yes, absolute NO
        ("C:", true, false),                   // bare drive: prefix yes, absolute NO
        ("/unix/path", false, false),          // unix absolute: neither
        ("bare", false, false),                // bare relative: neither
    ];
    for &(input, expect_prefix, expect_abs) in cases {
        assert_eq!(
            has_windows_drive_prefix(input),
            expect_prefix,
            "has_windows_drive_prefix({input:?})"
        );
        assert_eq!(
            is_windows_absolute(input),
            expect_abs,
            "is_windows_absolute({input:?})"
        );
    }
}

/// `C:\` and `C:/` are the only two absolute forms; the strict predicate treats
/// both separators identically and rejects a non-separator third byte.
#[test]
fn winpath_absolute_requires_separator_third_byte() {
    assert!(is_windows_absolute("C:\\a"));
    assert!(is_windows_absolute("C:/a"));
    // Third byte is a letter, not a separator -> drive-relative, not absolute.
    assert!(!is_windows_absolute("C:x"));
    // ...but it IS still drive-prefixed.
    assert!(has_windows_drive_prefix("C:x"));
}

/// The strict set is a strict SUBSET of the broad set: every absolute path is
/// drive-prefixed, but not vice versa. Verified as an implication over inputs.
#[test]
fn winpath_strict_implies_broad() {
    let absolutes = ["C:/a", "C:\\a", "z:/x", "D:\\dir\\file"];
    for p in absolutes {
        assert!(is_windows_absolute(p), "expected absolute: {p:?}");
        assert!(
            has_windows_drive_prefix(p),
            "absolute must imply prefix: {p:?}"
        );
    }
    // Drive-prefixed but NOT absolute -> the subset is strict.
    for p in ["C:", "C:rel", "q:file"] {
        assert!(has_windows_drive_prefix(p), "expected prefix: {p:?}");
        assert!(!is_windows_absolute(p), "must NOT be absolute: {p:?}");
    }
}

/// Adversarial/boundary: a leading digit is not a drive letter, a leading colon
/// is not a prefix, empty is neither, and lowercase drive letters are accepted.
#[test]
fn winpath_boundary_and_adversarial() {
    assert!(!has_windows_drive_prefix("1:oops")); // digit is not alphabetic
    assert!(!is_windows_absolute("1:/oops"));
    assert!(!has_windows_drive_prefix(":C")); // colon first
    assert!(!has_windows_drive_prefix("")); // empty
    assert!(!is_windows_absolute("")); // empty
    assert!(!has_windows_drive_prefix("C")); // single letter, no colon
    assert!(has_windows_drive_prefix("z:file")); // lowercase drive letter
    assert!(is_windows_absolute("d:/data")); // lowercase absolute
}

// ---------------------------------------------------------------------------
// ascii_ci: starts_with / ends_with / contains, ASCII case only.
// ---------------------------------------------------------------------------

/// starts_with_ignore_ascii_case folds ASCII case for the prefix, and an empty
/// prefix always matches while an over-long prefix never does.
#[test]
fn ascii_ci_starts_with_exact() {
    assert!(starts_with_ignore_ascii_case("HTTPS://host", "https"));
    assert!(starts_with_ignore_ascii_case("Bearer TOKEN", "bEaReR"));
    assert!(!starts_with_ignore_ascii_case("Authorization", "bearer"));
    // Empty prefix always matches.
    assert!(starts_with_ignore_ascii_case("anything", ""));
    // Prefix longer than value never matches.
    assert!(!starts_with_ignore_ascii_case("ab", "abc"));
}

/// ends_with_ignore_ascii_case (byte-based) folds ASCII case for the suffix;
/// empty suffix always matches, an over-long suffix never does, and a suffix
/// that appears only at the FRONT does not match.
#[test]
fn ascii_ci_ends_with_exact() {
    assert!(ends_with_ignore_ascii_case(b"archive.TAR.gz", b".tar.GZ"));
    assert!(ends_with_ignore_ascii_case(b"EXAMPLE", b"example"));
    assert!(ends_with_ignore_ascii_case(b"anything", b"")); // empty suffix
    assert!(ends_with_ignore_ascii_case(b"", b"")); // empty/empty
    assert!(!ends_with_ignore_ascii_case(b".gz", b"archive.gz")); // suffix longer
    assert!(!ends_with_ignore_ascii_case(b"file.json", b".yaml")); // no match
    assert!(!ends_with_ignore_ascii_case(b"yaml.file", b"yaml")); // front only
}

/// contains_ignore_ascii_case folds ASCII case for the needle; empty needle
/// always matches; boundary needle == whole value matches; over-long fails.
#[test]
fn ascii_ci_contains_exact() {
    assert!(contains_ignore_ascii_case(
        "my SECRET_key here",
        "secret_KEY"
    ));
    assert!(contains_ignore_ascii_case("PREFIXvalue", "prefix"));
    assert!(contains_ignore_ascii_case("suffixVALUE", "value"));
    assert!(contains_ignore_ascii_case("exact", "EXACT")); // whole-value needle
    assert!(contains_ignore_ascii_case("anything", "")); // empty needle
    assert!(!contains_ignore_ascii_case("short", "longerneedle")); // over-long
    assert!(!contains_ignore_ascii_case("password", "secret")); // absent
}

/// contains_bytes_ignore_ascii_case matches contains_ignore_ascii_case for the
/// same inputs, taking a byte-slice needle.
#[test]
fn ascii_ci_contains_bytes_matches_str_variant() {
    let value = "AWS_ACCESS_key_ID";
    assert!(contains_bytes_ignore_ascii_case(value, b"access_KEY"));
    assert!(contains_bytes_ignore_ascii_case(value, b"")); // empty needle
    assert!(!contains_bytes_ignore_ascii_case(value, b"secret"));
    // Parity with the &str variant on a shared needle.
    assert_eq!(
        contains_bytes_ignore_ascii_case(value, b"aws_access"),
        contains_ignore_ascii_case(value, "aws_access"),
    );
}

/// Adversarial: case folding is ASCII-ONLY. Non-ASCII letters are compared
/// byte-exact, so an upper/lower mismatch on a multibyte character does NOT
/// fold. The ASCII letters around it still fold.
#[test]
fn ascii_ci_non_ascii_is_not_folded() {
    // "é" (U+00E9, bytes C3 A9) vs "É" (U+00C9, bytes C3 89) differ in their
    // second UTF-8 byte, which is not an ASCII letter, so ASCII-only folding
    // cannot equate them: the substring search FAILS.
    assert!(!contains_ignore_ascii_case(
        "caf\u{00e9}_key",
        "CAF\u{00c9}_KEY"
    ));
    // Byte-identical non-ASCII char + ASCII case fold around it: SUCCEEDS.
    assert!(contains_ignore_ascii_case(
        "caf\u{00e9}_KEY",
        "CAF\u{00e9}_key"
    ));
    // ends_with: differing-case non-ASCII char does not fold (é vs É).
    assert!(!ends_with_ignore_ascii_case(
        "caf\u{00e9}".as_bytes(),
        "\u{00c9}".as_bytes()
    ));
    // ends_with: identical non-ASCII char with ASCII case folding before it.
    assert!(ends_with_ignore_ascii_case(
        "CAF\u{00e9}".as_bytes(),
        "caf\u{00e9}".as_bytes()
    ));
}

// ---------------------------------------------------------------------------
// git_lfs: pointer recognition, real pointer vs near-misses.
// ---------------------------------------------------------------------------

fn real_pointer() -> String {
    // 64 lowercase hex chars for the sha256 oid.
    let oid = "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393";
    assert_eq!(oid.len(), 64, "test fixture oid must be 64 hex chars");
    format!("version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 12345\n")
}

/// The canonical version-line constant is byte-exact, and recognition folds
/// ASCII case and trims surrounding whitespace.
#[test]
fn git_lfs_version_line_exact() {
    assert_eq!(
        GIT_LFS_VERSION_LINE,
        "version https://git-lfs.github.com/spec/v1"
    );
    assert!(is_git_lfs_version_line(GIT_LFS_VERSION_LINE.as_bytes()));
    // Surrounding ASCII whitespace is trimmed.
    assert!(is_git_lfs_version_line(
        b"  version https://git-lfs.github.com/spec/v1  "
    ));
    // Case-insensitive (content classification, not byte-exact parsing).
    assert!(is_git_lfs_version_line(
        b"VERSION HTTPS://GIT-LFS.GITHUB.COM/SPEC/V1"
    ));
    // A different spec URL is NOT the version line.
    assert!(!is_git_lfs_version_line(
        b"version https://git-lfs.github.com/spec/v2"
    ));
    assert!(!is_git_lfs_version_line(b"oid sha256:deadbeef"));
}

/// oid-line recognition requires exactly 64 hex chars after the `oid sha256:`
/// prefix; 63 or 65 chars, or a non-hex char, are rejected.
#[test]
fn git_lfs_oid_line_length_and_hex_boundary() {
    let hex64 = "a".repeat(64);
    assert!(is_git_lfs_oid_line(
        format!("oid sha256:{hex64}").as_bytes()
    ));
    // 63 hex -> too short.
    let hex63 = "a".repeat(63);
    assert!(!is_git_lfs_oid_line(
        format!("oid sha256:{hex63}").as_bytes()
    ));
    // 65 hex -> too long.
    let hex65 = "a".repeat(65);
    assert!(!is_git_lfs_oid_line(
        format!("oid sha256:{hex65}").as_bytes()
    ));
    // 64 chars but one is non-hex ('g').
    let mut nonhex = "a".repeat(63);
    nonhex.push('g');
    assert!(!is_git_lfs_oid_line(
        format!("oid sha256:{nonhex}").as_bytes()
    ));
    // Wrong prefix (md5 instead of sha256).
    assert!(!is_git_lfs_oid_line(format!("oid md5:{hex64}").as_bytes()));
}

/// size-line recognition requires the `size ` prefix and a non-empty run of
/// ASCII digits.
#[test]
fn git_lfs_size_line_boundary() {
    assert!(is_git_lfs_size_line(b"size 12345"));
    assert!(is_git_lfs_size_line(b"  size 0  ")); // trimmed, single digit ok
    assert!(!is_git_lfs_size_line(b"size ")); // empty numeric body
    assert!(!is_git_lfs_size_line(b"size 12x")); // non-digit in body
    assert!(!is_git_lfs_size_line(b"size")); // missing space+body
    assert!(!is_git_lfs_size_line(b"length 12345")); // wrong key
}

/// A well-formed whole pointer file is recognized; optional `ext-*` lines
/// between `version` and `oid` are tolerated.
#[test]
fn git_lfs_pointer_positive() {
    assert!(is_git_lfs_pointer(real_pointer().as_bytes()));
    // ext-* line tolerated between version and oid.
    let oid = "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393";
    let with_ext = format!(
        "version https://git-lfs.github.com/spec/v1\next-0-foo sha256:bar\noid sha256:{oid}\nsize 42\n"
    );
    assert!(is_git_lfs_pointer(with_ext.as_bytes()));
    // CRLF line endings are handled (split on \r and \n).
    let crlf = real_pointer().replace('\n', "\r\n");
    assert!(is_git_lfs_pointer(crlf.as_bytes()));
}

/// Near-misses: missing size, out-of-order (size before oid), truncated oid,
/// and plain non-pointer content are all rejected. A false positive here would
/// suppress a real credential, so strictness is load-bearing.
#[test]
fn git_lfs_pointer_near_misses_rejected() {
    let oid = "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393";
    // Missing size line.
    let no_size = format!("version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\n");
    assert!(!is_git_lfs_pointer(no_size.as_bytes()));
    // Out of order: size before oid (spec mandates oid then size).
    let out_of_order =
        format!("version https://git-lfs.github.com/spec/v1\nsize 12345\noid sha256:{oid}\n");
    assert!(!is_git_lfs_pointer(out_of_order.as_bytes()));
    // Truncated oid (63 hex) -> oid line not recognized -> no pointer.
    let short = "a".repeat(63);
    let bad_oid =
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{short}\nsize 1\n");
    assert!(!is_git_lfs_pointer(bad_oid.as_bytes()));
    // Missing version line.
    let no_version = format!("oid sha256:{oid}\nsize 12345\n");
    assert!(!is_git_lfs_pointer(no_version.as_bytes()));
    // Plain text that merely mentions git-lfs is not a pointer.
    assert!(!is_git_lfs_pointer(
        b"This repo uses git-lfs for large blobs.\n"
    ));
    // Empty content.
    assert!(!is_git_lfs_pointer(b""));
}

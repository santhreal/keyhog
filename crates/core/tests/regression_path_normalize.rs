//! Regression coverage for core PATH NORMALIZATION semantics.
//!
//! Two ONE-PLACE surfaces are exercised here:
//!   1. `keyhog_core::winpath::{has_windows_drive_prefix, is_windows_absolute}` 
//!      the BROAD (drive-prefix) vs STRICT (root-anchored) same-name-divergence
//!      predicates. This file asserts the RELATIONSHIP between the two and a set
//!      of boundary bools that are DISTINCT from `tests/unit/winpath.rs` (bare
//!      `C:\`, bare `C:/`, `AB:/x`, `://x`).
//!   2. The lexical path canonicaliser reached through the public
//!      `Allowlist::is_path_ignored`: `normalize_path` collapses `.`/`..`,
//!      folds backslashes to `/`, strips the leading unix root, and drops
//!      trailing/duplicate separators, applied to BOTH the ignore pattern and
//!      the queried path. Every case pins the concrete normalized form by
//!      observing an exact match/non-match bool.
//!   3. The SARIF URI relativiser (`sarif_relative_to` / `file_path_to_sarif_uri`
//!      on the `CoreTestApi` testing facade), asserting concrete rendered
//!      strings.
//!
//! HOST-INDEPENDENCE: none of these paths touch an accelerator or the
//! filesystem. `normalize_path` is a pure lexical transform over the given
//! string (`Path::components()` is not a syscall), and every SARIF case either
//! uses the pure `sarif_relative_to(path, explicit_root)` form or the
//! windows-absolute branch of `file_path_to_sarif_uri`, which resolves to a
//! `file:///` URI regardless of the process CWD (a Windows path can never be a
//! child of the unix scan root, so relativisation deterministically declines).
//! Component classification follows the compile target's rules (unix on the
//! test host), so a drive letter is a plain path segment here, asserted
//! explicitly rather than assumed.
//!
//! TEST TRUTH: every assertion is an exact bool / exact `Option<&str>` / exact
//! rendered `String`. No `is_empty()`/`is_some()`-only checks.

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::winpath::{has_windows_drive_prefix, is_windows_absolute};
use keyhog_core::Allowlist;
use std::path::Path;

/// Build an allowlist from a single `path:` ignore rule.
fn ignore(pattern: &str) -> Allowlist {
    let content = format!("path:{pattern}\n");
    CoreTestApi::allowlist_parse(&TestApi, &content)
}

// ---------------------------------------------------------------------------
// normalize_path via Allowlist::is_path_ignored (pure lexical canonicalisation)
// ---------------------------------------------------------------------------

#[test]
fn dotdot_parent_collapses_to_basename() {
    // `./a/../b` -> `b`: the `.` is dropped, `a` is popped by the following
    // `..`, leaving the single basename that the literal pattern matches.
    let al = ignore("b");
    assert_eq!(al.is_path_ignored("./a/../b"), true);
    // Control: the already-collapsed form matches identically.
    assert_eq!(al.is_path_ignored("b"), true);
}

#[test]
fn dotdot_collapse_negative_twin_differs_by_basename() {
    // `./a/../c` -> `c`, which is NOT the ignored basename `b`. The collapse is
    // lexical, so a one-character difference in the surviving segment misses.
    let al = ignore("b");
    assert_eq!(al.is_path_ignored("./a/../c"), false);
}

#[test]
fn trailing_slash_on_query_is_normalized_away() {
    // `a/b/` normalizes to `a/b` (a trailing separator yields no extra
    // component), so it matches the two-segment literal pattern; a genuine
    // third segment does not.
    let al = ignore("a/b");
    assert_eq!(al.is_path_ignored("a/b/"), true);
    assert_eq!(al.is_path_ignored("a/b"), true);
    assert_eq!(al.is_path_ignored("a/b/c"), false);
}

#[test]
fn backslash_and_mixed_separators_fold_to_forward_slash() {
    // `a\b\c` -> `a/b/c`: every backslash becomes `/` before component
    // splitting, so a Windows-authored path matches a forward-slash pattern.
    let al = ignore("a/b/c");
    assert_eq!(al.is_path_ignored("a\\b\\c"), true);
    assert_eq!(al.is_path_ignored("a\\b/c"), true);
    // A prefix of the pattern (only two of three segments) must not match.
    assert_eq!(al.is_path_ignored("a/b"), false);
}

#[test]
fn leading_unix_root_is_stripped() {
    // A leading `/` clears accumulated segments (root reset), so `/etc/passwd`
    // normalizes to the root-relative `etc/passwd` and matches the pattern.
    let al = ignore("etc/passwd");
    assert_eq!(al.is_path_ignored("/etc/passwd"), true);
    assert_eq!(al.is_path_ignored("etc/passwd"), true);
    assert_eq!(al.is_path_ignored("/etc/shadow"), false);
}

#[test]
fn windows_drive_letter_is_a_plain_segment_on_unix_host() {
    // On the (unix) test target a leading `C:` is NOT a filesystem prefix; it is
    // an ordinary `Normal` component. So `C:\Users\me` folds to the segment
    // sequence `C:` / `Users` / `me` and matches the equivalent pattern.
    let al = ignore("C:/Users/me");
    assert_eq!(al.is_path_ignored("C:\\Users\\me"), true);
    assert_eq!(al.is_path_ignored("C:/Users/me"), true);
    assert_eq!(al.is_path_ignored("C:\\Users\\you"), false);
}

#[test]
fn dotdot_beyond_root_is_retained_not_dropped() {
    // `a/../../b`: the first `..` pops `a`, the second `..` has nothing to pop
    // and is preserved, giving `../b`. A single `..` (`a/../b` -> `b`) does not
    // match the retained-`..` pattern.
    let al = ignore("../b");
    assert_eq!(al.is_path_ignored("a/../../b"), true);
    assert_eq!(al.is_path_ignored("../b"), true);
    assert_eq!(al.is_path_ignored("a/../b"), false);
}

#[test]
fn duplicate_separators_collapse() {
    // `a//b` -> `a/b`: the empty component between the doubled slash is dropped.
    let al = ignore("a/b");
    assert_eq!(al.is_path_ignored("a//b"), true);
    assert_eq!(al.is_path_ignored("a///b"), true);
}

#[test]
fn empty_query_path_never_matches_a_literal_pattern() {
    // The empty string normalizes to zero segments; a single-segment literal
    // pattern can never match a zero-segment path. Boundary/adversarial.
    let al = ignore("a");
    assert_eq!(al.is_path_ignored(""), false);
    // `.` alone also normalizes to zero segments.
    assert_eq!(al.is_path_ignored("."), false);
    assert_eq!(al.is_path_ignored("./"), false);
}

// ---------------------------------------------------------------------------
// winpath predicates: exact bools + the same-name-divergence relationship
// ---------------------------------------------------------------------------

#[test]
fn is_windows_absolute_exact_boundary_bools() {
    // STRICT sense: needs drive letter + colon + a separator at byte 2.
    // Minimal root-anchored forms (bare `C:\` and `C:/`) are absolute.
    assert_eq!(is_windows_absolute("C:\\"), true);
    assert_eq!(is_windows_absolute("C:/"), true);
    assert_eq!(is_windows_absolute("z:/x"), true);
    // Two-letter "drive" (`AB:`) fails: byte 1 is `B`, not `:`.
    assert_eq!(is_windows_absolute("AB:/x"), false);
    // Non-alphabetic leading byte fails even with a following separator.
    assert_eq!(is_windows_absolute("://x"), false);
    // Colon present but next byte is not a separator -> drive-relative, not
    // absolute.
    assert_eq!(is_windows_absolute("C:\n"), false);
}

#[test]
fn drive_prefix_and_absolute_diverge_on_the_same_string() {
    // The whole point of the ONE-PLACE split: a bare drive and a drive-relative
    // path carry a drive PREFIX (broad reject sense) yet are NOT absolute
    // (strict root-anchored sense).
    assert_eq!(has_windows_drive_prefix("C:"), true);
    assert_eq!(is_windows_absolute("C:"), false);

    assert_eq!(has_windows_drive_prefix("C:evil"), true);
    assert_eq!(is_windows_absolute("C:evil"), false);

    // A fully-qualified path satisfies BOTH predicates.
    assert_eq!(has_windows_drive_prefix("C:\\dir"), true);
    assert_eq!(is_windows_absolute("C:\\dir"), true);

    // A plain relative path satisfies NEITHER.
    assert_eq!(has_windows_drive_prefix("relative/path"), false);
    assert_eq!(is_windows_absolute("relative/path"), false);
}

// ---------------------------------------------------------------------------
// SARIF URI relativisation / rendering (concrete strings, CWD-independent)
// ---------------------------------------------------------------------------

#[test]
fn sarif_relative_to_repo_relative_and_outside_root() {
    // Under the explicit root -> forward-slashed repo-relative path.
    let inside = TestApi.sarif_relative_to("/repo/src/x.env", Path::new("/repo"));
    assert_eq!(inside.as_deref(), Some("src/x.env"));
    // Outside the root -> None (fail-closed; caller emits an absolute file://).
    let outside = TestApi.sarif_relative_to("/other/x.env", Path::new("/repo"));
    assert_eq!(outside.as_deref(), None);
}

#[test]
fn sarif_relative_to_folds_backslashes_and_handles_root_identity() {
    // Backslashes in the input are folded before and after stripping the root.
    let mixed = TestApi.sarif_relative_to("/repo\\src\\a.env", Path::new("/repo"));
    assert_eq!(mixed.as_deref(), Some("src/a.env"));
    // Path identical to the root strips to the empty relative path.
    let root_itself = TestApi.sarif_relative_to("/repo", Path::new("/repo"));
    assert_eq!(root_itself.as_deref(), Some(""));
}

#[test]
fn file_path_to_sarif_uri_windows_absolute_renders_file_scheme() {
    // A Windows-absolute path can never live under the unix scan root, so
    // relativisation deterministically declines and the strict-absolute branch
    // renders a `file:///` URI with backslashes folded to `/`. CWD-independent.
    let uri = TestApi.file_path_to_sarif_uri("C:\\proj\\secret.env");
    assert_eq!(uri, "file:///C:/proj/secret.env");
}

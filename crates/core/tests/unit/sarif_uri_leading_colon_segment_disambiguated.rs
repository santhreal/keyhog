//! A repo-relative SARIF `artifactLocation.uri` whose FIRST path segment
//! contains a `:` is ambiguous with a scheme (RFC 3986 §4.2): `a:b.env` parses
//! as scheme `a`, so GitHub code-scanning can't resolve it against the checkout
//! and the alert is dropped. Colons are legal POSIX filename characters, so this
//! is reachable from a real scan. The renderer prefixes such a path with `./`.

use keyhog_core::testing::{CoreTestApi, TestApi};

fn uri(path: &str) -> String {
    CoreTestApi::file_path_to_sarif_uri(&TestApi, path)
}

#[test]
fn leading_colon_segment_is_prefixed_with_dot_slash() {
    // First segment `a:b.env` would be read as scheme `a` — must become `./a:b.env`.
    assert_eq!(uri("a:b.env"), "./a:b.env");
    // A bare colon-bearing first segment with no slash is the same hazard.
    assert_eq!(uri("weird:name"), "./weird:name");
}

#[test]
fn colon_in_a_later_segment_is_left_unchanged() {
    // `dir` is the first segment and has no colon, so `dir/a:b.env` is already an
    // unambiguous relative reference — no `./` is added.
    assert_eq!(uri("dir/a:b.env"), "dir/a:b.env");
    assert_eq!(uri("nested/deep/x:y.txt"), "nested/deep/x:y.txt");
}

#[test]
fn colon_free_relative_paths_are_untouched() {
    // Regression guard: the common case must not gain a spurious `./` prefix.
    assert_eq!(uri("config.env"), "config.env");
    assert_eq!(uri("src/lib.rs"), "src/lib.rs");
    assert_eq!(uri("a/b/c.txt"), "a/b/c.txt");
}

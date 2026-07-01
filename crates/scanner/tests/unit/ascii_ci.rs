//! Migrated from src/ascii_ci.rs

use keyhog_scanner::testing::ascii_ci::{
    ci_find, ci_find_at, ci_find_nonempty, contains_path_segment, contains_path_segment_two,
    extend_ascii_lowercase_from, has_ascii_uppercase,
};

#[test]
fn extend_ascii_lowercase_from_appends_folded_bytes_once() {
    let mut out = b"prefix:".to_vec();
    extend_ascii_lowercase_from(&mut out, b"AaZz09_\0\xff");

    assert_eq!(&out, b"prefix:aazz09_\0\xff");
}

#[test]
fn extend_ascii_lowercase_from_matches_make_ascii_lowercase_semantics() {
    let src: Vec<u8> = (0u8..=255).collect();
    let mut expected = src.to_vec();
    expected.make_ascii_lowercase();

    let mut actual = Vec::new();
    extend_ascii_lowercase_from(&mut actual, &src);

    assert_eq!(actual, expected);
}

#[test]
fn extend_ascii_lowercase_from_matches_make_ascii_lowercase_for_long_tail() {
    let src: Vec<u8> = (0..4099)
        .map(|idx| ((idx * 37 + 11) & 0xff) as u8)
        .collect();
    let mut expected = b"prefix:".to_vec();
    expected.extend_from_slice(&src);
    expected[b"prefix:".len()..].make_ascii_lowercase();

    let mut actual = b"prefix:".to_vec();
    extend_ascii_lowercase_from(&mut actual, &src);

    assert_eq!(actual, expected);
}

#[test]
fn extend_ascii_lowercase_from_writes_initialized_spare_capacity() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ascii_ci.rs"));

    assert!(
        src.contains("spare_capacity_mut()") && src.contains("set_len(old_len + src.len())"),
        "hot GPU lowercase staging must initialize spare Vec capacity directly"
    );
    assert!(
        src.contains("write_ascii_lowercase_avx2")
            && src.contains("std::is_x86_feature_detected!(\"avx2\")")
            && src.contains("write_ascii_lowercase_neon")
            && src.contains("write_ascii_lowercase_simd_prefix")
            && src.contains("ascii_lower_branchless"),
        "hot GPU lowercase staging must keep x86_64 AVX2 and aarch64 NEON prefixes with a scalar tail"
    );
    assert!(
        !src.contains("extend(src.iter().map"),
        "hot GPU lowercase staging must not return to iterator-driven Vec::extend"
    );
}

#[test]
fn has_ascii_uppercase_matches_scalar_byte_semantics() {
    let bytes: Vec<u8> = (0u8..=255).collect();
    assert_eq!(
        has_ascii_uppercase(&bytes),
        bytes.iter().any(u8::is_ascii_uppercase)
    );

    let mut no_uppercase: Vec<u8> = (0..4099)
        .map(|idx| {
            let byte = ((idx * 37 + 11) & 0xff) as u8;
            byte.to_ascii_lowercase()
        })
        .collect();
    no_uppercase.retain(|byte| !byte.is_ascii_uppercase());
    assert!(!has_ascii_uppercase(&no_uppercase));

    let mut long_tail = no_uppercase.clone();
    long_tail.extend_from_slice(b"zzzzZ");
    assert!(has_ascii_uppercase(&long_tail));
}

#[test]
fn has_ascii_uppercase_keeps_simd_and_scalar_owner_in_ascii_ci() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ascii_ci.rs"));

    assert!(
        src.contains("fn has_ascii_uppercase")
            && src.contains("has_ascii_uppercase_avx2")
            && src.contains("has_ascii_uppercase_neon")
            && src.contains("ascii_is_uppercase"),
        "ASCII uppercase detection for GPU zero-copy admission must stay in the ascii_ci owner"
    );
}

#[test]
fn ci_find_matches_case_insensitively() {
    assert!(ci_find(b"Hello WORLD", b"hello"));
    assert!(ci_find(b"Hello WORLD", b"world"));
    assert!(ci_find(b"prefix INTEGRITY suffix", b"integrity"));
}

#[test]
fn ci_find_empty_needle_is_true() {
    assert!(ci_find(b"anything", b""));
}

#[test]
fn ci_find_nonempty_empty_needle_is_false() {
    assert!(!ci_find_nonempty(b"anything", b""));
}

#[test]
fn ci_find_nonempty_handles_configured_mixed_case_needles() {
    assert!(ci_find_nonempty(b"api_key=abc123", b"API_KEY"));
    assert!(ci_find_nonempty(b"PLACEHOLDER_TOKEN", b"placeholder"));
    assert!(!ci_find_nonempty(b"api_key=abc123", b"SECRET_KEY"));
}

#[test]
fn ci_find_needle_longer_than_haystack_is_false() {
    assert!(!ci_find(b"hi", b"hello"));
}

#[test]
fn ci_find_no_match_is_false() {
    assert!(!ci_find(b"nothing here", b"integrity"));
}

#[test]
fn contains_path_segment_posix() {
    assert!(contains_path_segment(
        "/home/me/app/node_modules/foo.js",
        "node_modules"
    ));
}

#[test]
fn contains_path_segment_windows() {
    assert!(contains_path_segment(
        "C:\\src\\app\\node_modules\\foo.js",
        "node_modules"
    ));
}

#[test]
fn contains_path_segment_case_insensitive() {
    assert!(contains_path_segment(
        "/Home/Me/App/NODE_MODULES/foo.js",
        "node_modules"
    ));
}

#[test]
fn contains_path_segment_negative() {
    assert!(!contains_path_segment(
        "/home/me/app/src/foo.js",
        "node_modules"
    ));
    assert!(!contains_path_segment(
        "/home/me/node_modules2/foo.js",
        "node_modules"
    ));
}

#[test]
fn contains_path_segment_leading_relative_posix() {
    // Bug (Gemini Iter-3 / µ-ci-15): a segment at the absolute START of a
    // relative path had no preceding separator, so the separator-anchored loop
    // skipped it and vendored-tree suppression silently failed on relative roots
    // (`keyhog scan node_modules`). The leading non-`.min.js` file must match.
    assert!(contains_path_segment(
        "node_modules/foo/index.js",
        "node_modules"
    ));
    assert!(contains_path_segment(
        "site-packages/pkg/mod.py",
        "site-packages"
    ));
    // Windows-shape relative path.
    assert!(contains_path_segment(
        "node_modules\\foo\\index.js",
        "node_modules"
    ));
    // The directory itself with a trailing separator still counts.
    assert!(contains_path_segment("node_modules/", "node_modules"));
}

#[test]
fn contains_path_segment_leading_negative_twin() {
    // The leading fix must NOT introduce a substring false-match: a prefix that
    // merely STARTS with the segment but is a different directory name must not
    // suppress. `node_modules2/` and `node_modulesX/` are real directories.
    assert!(!contains_path_segment(
        "node_modules2/foo.js",
        "node_modules"
    ));
    assert!(!contains_path_segment("nodemodules/foo.js", "node_modules"));
    // Bare segment with nothing after (no trailing separator) is not a tree.
    assert!(!contains_path_segment("node_modules", "node_modules"));
}

#[test]
fn contains_path_segment_two_leading_relative() {
    // Two-segment start-of-path twin: `public/plugins/...` at offset 0.
    assert!(contains_path_segment_two(
        "public/plugins/foo/foo.js",
        "public",
        "plugins"
    ));
    assert!(contains_path_segment_two(
        "public\\plugins\\foo\\foo.js",
        "public",
        "plugins"
    ));
    // Negative twin: first segment is a prefix but a distinct directory.
    assert!(!contains_path_segment_two(
        "publicX/plugins/foo.js",
        "public",
        "plugins"
    ));
    // Negative twin: right first segment, wrong second.
    assert!(!contains_path_segment_two(
        "public/themes/foo.js",
        "public",
        "plugins"
    ));
}

#[test]
fn contains_path_segment_two_posix() {
    assert!(contains_path_segment_two(
        "/var/www/wp-content/plugins/foo/foo.js",
        "wp-content",
        "plugins"
    ));
}

#[test]
fn contains_path_segment_two_windows() {
    assert!(contains_path_segment_two(
        "C:\\inetpub\\wp-content\\plugins\\foo\\foo.js",
        "wp-content",
        "plugins"
    ));
}

#[test]
fn contains_path_segment_two_negative() {
    assert!(!contains_path_segment_two(
        "/var/www/wp-content/themes/foo/foo.js",
        "wp-content",
        "plugins"
    ));
}

// ---- ci_find_at: the position-returning case-insensitive substring search ----

#[test]
fn ci_find_at_returns_zero_when_needle_is_a_prefix() {
    assert_eq!(ci_find_at(b"sha256:deadbeef", b"sha256:"), Some(0));
}

#[test]
fn ci_find_at_returns_the_offset_of_an_embedded_match() {
    assert_eq!(ci_find_at(b"nginx@sha256:x", b"sha256:"), Some(6));
}

#[test]
fn ci_find_at_matches_case_insensitively_in_both_directions() {
    // Upper-case haystack, lower-case needle (ssh-keygen SHA256:).
    assert_eq!(ci_find_at(b"SHA256:x", b"sha256:"), Some(0));
    // Lower-case haystack, upper-case needle - the needle may be any case.
    assert_eq!(ci_find_at(b"sha256:x", b"SHA256:"), Some(0));
    // Mixed case on both sides still matches.
    assert_eq!(ci_find_at(b"xxShA256:", b"sHa256:"), Some(2));
}

#[test]
fn ci_find_at_returns_none_when_absent() {
    assert_eq!(ci_find_at(b"sha512-body", b"sha256:"), None);
    assert_eq!(ci_find_at(b"", b"x"), None);
}

#[test]
fn ci_find_at_empty_needle_is_not_found() {
    // Mirrors ci_find_nonempty: an empty needle must not match every offset.
    assert_eq!(ci_find_at(b"anything", b""), None);
    assert_eq!(ci_find_at(b"", b""), None);
}

#[test]
fn ci_find_at_needle_longer_than_haystack_is_none() {
    assert_eq!(ci_find_at(b"sha", b"sha256:"), None);
}

#[test]
fn ci_find_at_returns_first_of_multiple_occurrences() {
    assert_eq!(ci_find_at(b"abXABxab", b"ab"), Some(0));
    // First match is the upper-case one when it comes first.
    assert_eq!(ci_find_at(b"ZZABzzab", b"ab"), Some(2));
}

#[test]
fn ci_find_at_matches_at_the_very_end() {
    assert_eq!(ci_find_at(b"xxxxAB", b"ab"), Some(4));
}

#[test]
fn ci_find_nonempty_agrees_with_ci_find_at_presence() {
    // ci_find_nonempty delegates to ci_find_at; pin that they never diverge.
    for (h, n) in [
        (&b"sha256:x"[..], &b"sha256:"[..]),
        (&b"SHA256:x"[..], &b"sha256:"[..]),
        (&b"nope"[..], &b"sha256:"[..]),
        (&b"anything"[..], &b""[..]),
        (&b"ab"[..], &b"abc"[..]),
    ] {
        assert_eq!(ci_find_nonempty(h, n), ci_find_at(h, n).is_some());
    }
}

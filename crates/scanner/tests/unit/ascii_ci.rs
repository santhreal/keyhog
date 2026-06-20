//! Migrated from src/ascii_ci.rs

use keyhog_scanner::testing::ascii_ci::{
    ci_find, contains_path_segment, contains_path_segment_two, extend_ascii_lowercase_from,
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

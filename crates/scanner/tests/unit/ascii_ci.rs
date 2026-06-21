//! Migrated from src/ascii_ci.rs

use keyhog_scanner::testing::ascii_ci::{
    ci_find, ci_find_nonempty, contains_path_segment, contains_path_segment_two,
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

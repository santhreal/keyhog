//! Migrated from src/ascii_ci.rs

use keyhog_scanner::testing::ascii_ci::{
    ci_find, contains_path_segment, contains_path_segment_two,
};

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

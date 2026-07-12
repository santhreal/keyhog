//! Unit tests for `crate::subcommands::doctor` PATH-membership normalization.
//! Housed in a sibling `tests.rs` module (rather than an inline
//! `#[cfg(test)] mod {}` block) so the KH-GAP-004 `no_inline_tests_in_src` gate
//! stays green while still reaching the parent module's private
//! `dir_is_on_path` via `super::`.

use super::dir_is_on_path;
use std::ffi::OsString;

/// A PATH entry with a TRAILING SLASH still matches the install dir: the old
/// raw `d == dir` compare returned a false "on PATH: no" for `~/.local/bin/`.
#[test]
fn trailing_slash_path_entry_still_matches() {
    let dir = tempfile::tempdir().expect("tempdir");
    let install = dir.path().join("bin");
    std::fs::create_dir(&install).expect("mkdir bin");

    // PATH holds the same dir WITH a trailing separator, plus an unrelated dir.
    let mut with_slash = install.clone().into_os_string();
    with_slash.push(std::path::MAIN_SEPARATOR.to_string());
    let pathvar =
        std::env::join_paths([OsString::from("/nonexistent/x"), with_slash]).expect("join_paths");

    assert!(
        dir_is_on_path(&install, &pathvar),
        "a trailing-slash PATH entry must canonicalize-match the install dir"
    );
}

/// A dir genuinely absent from PATH reports false (no over-matching).
#[test]
fn dir_absent_from_path_reports_false() {
    let dir = tempfile::tempdir().expect("tempdir");
    let install = dir.path().join("bin");
    std::fs::create_dir(&install).expect("mkdir bin");
    let other = dir.path().join("other");
    std::fs::create_dir(&other).expect("mkdir other");

    let pathvar = std::env::join_paths([other.into_os_string()]).expect("join_paths");
    assert!(
        !dir_is_on_path(&install, &pathvar),
        "an install dir not present in PATH must report false"
    );
}

//! Behavioral truth table for `platform_compat::path_basename`, the single
//! cross-platform final-component extractor every suppression/context path uses
//! for file attribution. The existing `cross_platform_cfg_gates_absent` gate only
//! asserts the OWNER exists (source-shape: `contains("fn path_basename(")`), it
//! never exercises the mixed-separator behavior. Since keyhog scans repos that
//! carry BOTH `/` (POSIX) and `\` (Windows-authored) paths, sometimes MIXED in
//! one string (e.g. a Windows path embedded in a POSIX-checked-out repo)
//! getting the last component wrong misattributes a finding to the wrong file or
//! defeats a filename-based suppression. These pin the actual extraction.

use keyhog_scanner::testing::path_basename_for_test as basename;

#[test]
fn posix_path_returns_final_component() {
    assert_eq!(basename("/usr/local/bin/tool"), "tool");
}

#[test]
fn windows_path_returns_final_component() {
    assert_eq!(basename(r"C:\Users\admin\id_rsa"), "id_rsa");
}

/// The load-bearing case: a path that MIXES both separators must still cut at the
/// LAST separator of either kind, here the final `\`: not treat the whole
/// string (or the wrong half) as the basename.
#[test]
fn mixed_separators_cut_at_the_last_separator_of_either_kind() {
    assert_eq!(basename(r"repo/src\config\secret.env"), "secret.env");
    assert_eq!(basename(r"dir\sub/deploy.key"), "deploy.key");
}

#[test]
fn path_without_any_separator_is_its_own_basename() {
    assert_eq!(basename("plainfile.txt"), "plainfile.txt");
}

/// Documents the trailing-separator edge: the component AFTER the final separator
/// is empty, so the basename is `""`. Scanner file paths never carry a trailing
/// separator (they name files, not directories), so this is an edge, not a hot
/// path (pinned so a future change to the split is a conscious decision).
#[test]
fn trailing_separator_yields_empty_basename() {
    assert_eq!(basename("some/dir/"), "");
    assert_eq!(basename(r"some\dir\"), "");
}

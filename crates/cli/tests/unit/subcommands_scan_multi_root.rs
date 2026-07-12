//! Multi-root scanning (`keyhog scan a/ b/ c/`).
//!
//! keyhog scans several filesystem roots per invocation: each becomes its own
//! filesystem source (the scan engine already merges the multi-source `Vec`),
//! overlapping/nested roots fold into their covering parent, and the modes that
//! have no unambiguous meaning over more than one root fail closed. These tests
//! pin three layers:
//!   * the parse + [`ScanArgs::scan_roots`] accessor (pure),
//!   * the [`resolve_scan_roots`] overlap/validation resolver (via the
//!     `CliTestApi` facade, on real temp directories), and
//!   * the shipped binary end to end (every root is actually scanned and no
//!     finding is silently dropped — the recall contract this feature exists
//!     for).

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi, API};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A planted AWS access-key id — a deterministic high-confidence positive used
/// across the e2e suite, so a finding is guaranteed on any host/backend.
const PLANTED_SECRET: &str = "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n";

fn parse(argv: &[&str]) -> ScanArgs {
    ScanArgs::try_parse_from(argv).expect("scan args must parse")
}

// ---------------------------------------------------------------------------
// Layer 1 — `ScanArgs::scan_roots` accessor (pure)
// ---------------------------------------------------------------------------

#[test]
fn single_positional_is_one_root() {
    assert_eq!(parse(&["scan", "a"]).scan_roots(), vec![PathBuf::from("a")]);
}

#[test]
fn three_positionals_are_three_ordered_roots() {
    assert_eq!(
        parse(&["scan", "a", "b", "c"]).scan_roots(),
        vec![PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")],
    );
}

#[test]
fn explicit_path_flag_is_one_root() {
    assert_eq!(
        parse(&["scan", "--path", "p"]).scan_roots(),
        vec![PathBuf::from("p")],
    );
}

#[test]
fn no_path_is_zero_roots() {
    assert!(parse(&["scan"]).scan_roots().is_empty());
}

#[test]
fn surplus_positionals_land_in_extra_paths() {
    let args = parse(&["scan", "a", "b", "c"]);
    assert_eq!(args.input.as_deref(), Some(Path::new("a")));
    let extras: Vec<&str> = args.extra_paths.iter().filter_map(|p| p.to_str()).collect();
    assert_eq!(extras, vec!["b", "c"]);
}

#[test]
fn scan_roots_survives_orchestrator_input_to_path_promotion() {
    // `ScanOrchestrator::new` copies the first positional `input` into `path`.
    // Reading `path` first would then drop every surplus root, so the accessor
    // must consult `extra_paths` first. Simulate the promotion explicitly.
    let mut args = parse(&["scan", "a", "b", "c"]);
    args.path = args.input.clone();
    assert_eq!(
        args.scan_roots(),
        vec![PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")],
        "promotion must not collapse a multi-root request to its first root",
    );
}

// ---------------------------------------------------------------------------
// Layer 2 — `resolve_scan_roots` validation + overlap fold (real dirs)
// ---------------------------------------------------------------------------

#[test]
fn distinct_roots_are_kept_in_order() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();

    let kept = API
        .resolve_scan_roots(&[a.clone(), b.clone()])
        .expect("two distinct roots resolve");
    assert_eq!(kept, vec![a, b]);
}

#[test]
fn exact_duplicate_root_is_folded_to_one() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a");
    std::fs::create_dir(&a).unwrap();

    let kept = API
        .resolve_scan_roots(&[a.clone(), a.clone()])
        .expect("duplicate roots resolve");
    assert_eq!(kept, vec![a], "an exact duplicate keeps only the first");
}

#[test]
fn nested_child_after_parent_is_folded_into_parent() {
    let tmp = TempDir::new().expect("tempdir");
    let parent = tmp.path().join("parent");
    let child = parent.join("child");
    std::fs::create_dir_all(&child).unwrap();

    let kept = API
        .resolve_scan_roots(&[parent.clone(), child])
        .expect("nested roots resolve");
    assert_eq!(kept, vec![parent], "the child subtree is already walked");
}

#[test]
fn nested_parent_after_child_still_folds_the_child() {
    let tmp = TempDir::new().expect("tempdir");
    let parent = tmp.path().join("parent");
    let child = parent.join("child");
    std::fs::create_dir_all(&child).unwrap();

    // Order reversed: the ancestor wins regardless of argument position.
    let kept = API
        .resolve_scan_roots(&[child, parent.clone()])
        .expect("nested roots resolve");
    assert_eq!(kept, vec![parent]);
}

#[test]
fn only_the_nested_root_is_dropped_from_three() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    let a_sub = a.join("sub");
    std::fs::create_dir_all(&a_sub).unwrap();
    std::fs::create_dir(&b).unwrap();

    let kept = API
        .resolve_scan_roots(&[a.clone(), a_sub, b.clone()])
        .expect("mixed roots resolve");
    assert_eq!(kept, vec![a, b]);
}

#[test]
fn sibling_directories_are_both_kept() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("shared_a");
    let b = tmp.path().join("shared_b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();

    // `shared_b` is NOT nested in `shared_a` even though the canonical string of
    // one is a textual prefix of the other — `Path::starts_with` is
    // component-wise, so neither is folded.
    let kept = API
        .resolve_scan_roots(&[a.clone(), b.clone()])
        .expect("sibling roots resolve");
    assert_eq!(kept, vec![a, b]);
}

#[test]
fn single_root_resolves_to_itself() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a");
    std::fs::create_dir(&a).unwrap();
    assert_eq!(API.resolve_scan_roots(&[a.clone()]).unwrap(), vec![a]);
}

#[test]
fn empty_request_resolves_to_empty() {
    assert!(API.resolve_scan_roots(&[]).unwrap().is_empty());
}

#[test]
fn nonexistent_root_fails_closed() {
    let tmp = TempDir::new().expect("tempdir");
    let real = tmp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let missing = tmp.path().join("does_not_exist");

    let err = API
        .resolve_scan_roots(&[real, missing])
        .expect_err("a missing root must error, not be silently skipped");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("does_not_exist"),
        "the error names the offending root: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Layer 2b — combination guard (`guard_multi_root_combinations`)
// ---------------------------------------------------------------------------

#[test]
fn single_root_passes_the_combination_guard() {
    API.guard_multi_root_combinations(&parse(&["scan", "a"]))
        .expect("one root has nothing to guard");
}

#[test]
fn plain_multi_root_passes_the_combination_guard() {
    API.guard_multi_root_combinations(&parse(&["scan", "a", "b", "c"]))
        .expect("plain filesystem multi-root is allowed");
}

#[cfg(feature = "git")]
#[test]
fn git_staged_with_multi_root_is_rejected() {
    let err = API
        .guard_multi_root_combinations(&parse(&["scan", "a", "b", "--git-staged"]))
        .expect_err("--git-staged cannot span multiple roots");
    let msg = format!("{err:#}");
    assert!(msg.contains("--git-staged"), "names the flag: {msg}");
    assert!(
        msg.contains('a') && msg.contains('b'),
        "names the offending roots: {msg}"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_staged_with_single_root_is_allowed() {
    API.guard_multi_root_combinations(&parse(&["scan", "repo", "--git-staged"]))
        .expect("--git-staged is fine with exactly one root");
}

// ---------------------------------------------------------------------------
// Layer 3 — shipped binary, end to end
// ---------------------------------------------------------------------------

fn scan(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(binary())
        .arg("scan")
        .args(["--daemon=off", "--backend", "simd", "--format", "json"])
        .args(args)
        .output()
        .expect("spawn keyhog scan")
}

#[test]
fn two_clean_roots_scan_and_exit_zero() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    std::fs::write(a.join("clean.txt"), "nothing here\n").unwrap();
    std::fs::write(b.join("clean.txt"), "also nothing\n").unwrap();

    let out = scan(&[a.as_os_str(), b.as_os_str()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "two clean roots exit 0; stderr={stderr}"
    );
    assert!(
        !stderr.contains("scans one root path per invocation"),
        "multi-root is accepted, never rejected: {stderr}"
    );
}

#[test]
fn every_root_is_scanned_and_no_finding_is_dropped() {
    // The recall contract: a secret planted in EACH root must surface. Reading
    // only the first root (the pre-feature behavior) would drop `beta`.
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    std::fs::write(a.join("alpha.env"), PLANTED_SECRET).unwrap();
    std::fs::write(b.join("beta.env"), PLANTED_SECRET).unwrap();

    let out = scan(&[a.as_os_str(), b.as_os_str()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "findings present exit 1; stdout={stdout}"
    );
    assert!(stdout.contains("alpha.env"), "first root scanned: {stdout}");
    assert!(stdout.contains("beta.env"), "second root scanned: {stdout}");
    assert_eq!(
        stdout.matches("\"file_path\"").count(),
        2,
        "exactly one finding per root, none dropped or duplicated: {stdout}"
    );
}

#[test]
fn overlapping_roots_fold_loudly_and_scan_the_subtree_once() {
    let tmp = TempDir::new().expect("tempdir");
    let parent = tmp.path().join("parent");
    let child = parent.join("child");
    std::fs::create_dir_all(&child).unwrap();
    std::fs::write(child.join("planted.env"), PLANTED_SECRET).unwrap();

    let out = scan(&[parent.as_os_str(), child.as_os_str()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("folding overlapping scan root"),
        "the fold is announced, never silent (Law 10): {stderr}"
    );
    assert_eq!(
        stdout.matches("\"file_path\"").count(),
        1,
        "the nested subtree is walked once via its parent, not twice: {stdout}"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_staged_multi_root_binary_fails_closed() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();

    let out = Command::new(binary())
        .arg("scan")
        .args(["--daemon=off", "--backend", "simd", "--git-staged"])
        .args([a.as_os_str(), b.as_os_str()])
        .output()
        .expect("spawn keyhog scan");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "--git-staged over many roots fails closed with EXIT_USER_ERROR; stderr={stderr}"
    );
    assert!(
        stderr.contains("repository"),
        "explains the single-repository constraint: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn forced_daemon_with_multi_root_fails_closed_not_silent() {
    // `--daemon=on` over several roots cannot be served by the single-path
    // daemon protocol; it must fail closed rather than silently scan the first
    // root only.
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a.env");
    let b = tmp.path().join("b.env");
    std::fs::write(&a, PLANTED_SECRET).unwrap();
    std::fs::write(&b, PLANTED_SECRET).unwrap();

    let out = Command::new(binary())
        .arg("scan")
        .args(["--daemon=on", "--backend", "simd", "--format", "json"])
        .args([a.as_os_str(), b.as_os_str()])
        .output()
        .expect("spawn keyhog scan");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon + multi-root fails closed; stdout={stdout}"
    );
    assert!(
        !stdout.contains("a.env") || !stdout.contains("\"file_path\""),
        "it must NOT silently produce a single-root daemon result: {stdout}"
    );
}

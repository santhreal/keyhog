//! Multi-root scan-argument guard (relocated out of `subcommands/scan.rs` to
//! honor the Santh folder contract: no inline `#[cfg(test)]` in subcommand
//! source — gates `subcommands_scan_no_inline_tests` /
//! `subcommands_scan_no_unwrap_expect`).
//!
//! `keyhog` scans exactly one root per invocation. A hidden catch-all
//! positional (`ScanArgs::extra_paths`) captures any surplus paths so clap
//! does not reject them with an opaque error; `reject_multiple_scan_roots`
//! (run at the very top of `subcommands::scan::run`) then fails closed with
//! actionable guidance. These tests pin both halves:
//!   * the parse layer (clap routes the first positional to `input` and the
//!     rest to `extra_paths`), and
//!   * the real operator path (the shipped binary exits `EXIT_USER_ERROR = 2`
//!     with a message that names the offending paths and every workaround),
//! which is strictly stronger than the previous in-source unit assertions
//! because it drives the actual `keyhog` executable end to end.

use clap::Parser;
use keyhog::args::ScanArgs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// `keyhog scan a b c` must split into one root (`a`) plus the rest as
/// `extra_paths`, so the hidden catch-all actually captures the surplus
/// instead of clap erroring on "unexpected argument".
#[test]
fn extra_positional_paths_are_captured_not_rejected_by_clap() {
    let args = ScanArgs::try_parse_from(["scan", "a", "b", "c"])
        .expect("clap must accept multiple positionals via the hidden catch-all");
    assert_eq!(
        args.input.as_deref().and_then(|p| p.to_str()),
        Some("a"),
        "the first positional is the scan root"
    );
    let extras: Vec<&str> = args.extra_paths.iter().filter_map(|p| p.to_str()).collect();
    assert_eq!(
        extras,
        vec!["b", "c"],
        "surplus positionals land in extra_paths"
    );
}

/// Exactly one root carries no surplus, so the guard has nothing to reject.
#[test]
fn single_root_has_no_extra_paths() {
    let args =
        ScanArgs::try_parse_from(["scan", "only/one"]).expect("a single positional must parse");
    assert!(
        args.extra_paths.is_empty(),
        "a single root leaves extra_paths empty"
    );
}

/// A directory-less invocation (defaults to `.`) likewise carries no surplus.
#[test]
fn no_path_has_no_extra_paths() {
    let args = ScanArgs::try_parse_from(["scan"]).expect("a path-less scan must parse");
    assert!(
        args.extra_paths.is_empty(),
        "no positional leaves extra_paths empty"
    );
}

/// The shipped binary rejects multiple roots (not clap) with `EXIT_USER_ERROR`
/// and guidance that names the first root, the surplus roots, and every
/// documented workaround — and uses plural agreement for >1 surplus path.
#[test]
fn multiple_roots_fail_closed_with_actionable_message() {
    let output = Command::new(binary())
        .args(["scan", "src", "tests", "config"])
        .output()
        .expect("spawn keyhog scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "multiple roots must fail closed with EXIT_USER_ERROR=2; stderr={stderr}"
    );
    assert!(
        stderr.contains("keyhog scans one root path per invocation"),
        "states the single-root model: {stderr}"
    );
    assert!(stderr.contains("`src`"), "names the first root: {stderr}");
    assert!(
        stderr.contains("tests") && stderr.contains("config"),
        "names the surplus roots: {stderr}"
    );
    assert!(
        stderr.contains("common parent directory"),
        "offers the common-parent workaround: {stderr}"
    );
    assert!(
        stderr.contains("--exclude-paths"),
        "offers the narrow-with-exclude workaround: {stderr}"
    );
    assert!(
        stderr.contains("once per path"),
        "offers the per-path workaround: {stderr}"
    );
    assert!(
        stderr.contains("2 extra paths were given"),
        "plural agreement for two surplus paths: {stderr}"
    );
}

/// Singular agreement when exactly one surplus path is present.
#[test]
fn single_surplus_path_uses_singular_agreement() {
    let output = Command::new(binary())
        .args(["scan", "a", "b"])
        .output()
        .expect("spawn keyhog scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "two roots must fail closed with EXIT_USER_ERROR=2; stderr={stderr}"
    );
    assert!(
        stderr.contains("1 extra path was given"),
        "singular agreement for one surplus path: {stderr}"
    );
}

/// The common case — exactly one existing root — passes the guard end to end:
/// the shipped binary proceeds into the real scan and never emits the
/// multi-root rejection. An explicit `--backend cpu` is passed so the run is
/// deterministic on any host: it bypasses the autoroute-calibration
/// fail-closed (which would otherwise exit 2 on an uncalibrated box for an
/// unrelated reason), letting a clean, finding-free file exit 0.
#[test]
fn single_root_is_accepted_end_to_end() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "no secrets here\n").expect("write fixture");

    let output = Command::new(binary())
        .args(["scan", "--backend", "cpu"])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("keyhog scans one root path per invocation"),
        "a single root must pass the guard, not be rejected; stderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "a single clean root on an explicit cpu backend must scan and exit 0; stderr={stderr}"
    );
}

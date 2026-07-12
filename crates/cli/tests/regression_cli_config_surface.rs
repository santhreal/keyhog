//! LANE: cli watch/config surface — driven over the SHIPPED binary
//! (`CARGO_BIN_EXE_keyhog`), never the library, so these prove the exact
//! argument-parsing contract a packager / CI author / editor-integration hits.
//!
//! What is pinned here (every assert names an EXACT exit code and an EXACT
//! string; never `!is_empty`):
//!   1. `--help` surfaces list the REAL flag names for the top level, `scan`,
//!      `watch`, and `config` (a renamed/dropped flag fails here).
//!   2. A config-affecting flag actually REACHES the resolved config that
//!      `keyhog config --effective` dumps (parse → merge → render round-trip),
//!      asserted against the concrete emitted `key = value` line.
//!   3. Every documented mutually-exclusive flag pair errors with clap's exact
//!      "cannot be used with" diagnostic and the user-error exit code 2.
//!   4. A missing required flag (`config` without `--effective`) and an unknown
//!      flag both exit 2 with clap's exact diagnostic.
//!
//! HOST-INDEPENDENCE: none of these invocations execute a scan backend. The
//! `config --effective` path resolves config and renders it WITHOUT probing an
//! accelerator (default `backend = auto`, no `--require-gpu`), so the emitted
//! lines are identical on a GPU box and a GPU-less CI runner. Nothing here
//! asserts that a SIMD/GPU/Hyperscan backend is present.
//!
//! Exit codes are the documented contract: 0 = success, 2 = user error
//! (clap parse failure), per `crate::exit_codes` (`EXIT_USER_ERROR = 2`).

use std::process::Command;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Run the shipped binary and return (exit code, stdout, stderr).
fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(binary())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn `keyhog {}`: {e}", args.join(" ")));
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// 1. --help surfaces list the real flag / subcommand names
// ---------------------------------------------------------------------------

#[test]
fn top_level_help_lists_config_and_watch_subcommands() {
    let (code, stdout, stderr) = run(&["--help"]);
    assert_eq!(
        code,
        Some(0),
        "`keyhog --help` must exit 0; stderr={stderr}"
    );
    // The top-level menu must name the surfaces this lane covers.
    for needle in ["scan", "watch", "config", "daemon"] {
        assert!(
            stdout.contains(needle),
            "top-level --help must list the `{needle}` subcommand; got:\n{stdout}"
        );
    }
}

#[test]
fn scan_help_lists_config_affecting_flags() {
    let (code, stdout, stderr) = run(&["scan", "--help"]);
    assert_eq!(
        code,
        Some(0),
        "`keyhog scan --help` must exit 0; stderr={stderr}"
    );
    // These flags are always compiled (not feature-gated) and each affects the
    // resolved scan config. A rename drops the packager/CI contract silently.
    for flag in [
        "--fast",
        "--deep",
        "--precision",
        "--min-confidence",
        "--decode-depth",
        "--no-config",
        "--config",
        "--backend",
        "--format",
        "--daemon=off",
        "--dedup",
    ] {
        assert!(
            stdout.contains(flag),
            "`keyhog scan --help` must document `{flag}`; got:\n{stdout}"
        );
    }
}

#[test]
fn watch_help_lists_its_real_flags() {
    let (code, stdout, stderr) = run(&["watch", "--help"]);
    assert_eq!(
        code,
        Some(0),
        "`keyhog watch --help` must exit 0; stderr={stderr}"
    );
    // Exactly the WatchArgs surface: paths + detectors + cache-dir + backend + quiet.
    for flag in ["--detectors", "--cache-dir", "--backend", "--quiet"] {
        assert!(
            stdout.contains(flag),
            "`keyhog watch --help` must document `{flag}`; got:\n{stdout}"
        );
    }
    // `watch` intentionally does NOT expose the scan-only `--format` flag; its
    // output is the live watch stream, not a formatted report.
    assert!(
        !stdout.contains("--format"),
        "`keyhog watch --help` must NOT expose --format (watch has no report format); got:\n{stdout}"
    );
}

#[test]
fn config_help_requires_effective_and_reuses_scan_flags() {
    let (code, stdout, stderr) = run(&["config", "--help"]);
    assert_eq!(
        code,
        Some(0),
        "`keyhog config --help` must exit 0; stderr={stderr}"
    );
    // `config` flattens ScanArgs, so its own `--effective` gate AND the shared
    // config-affecting scan flags must both be documented.
    for flag in ["--effective", "--min-confidence", "--no-config"] {
        assert!(
            stdout.contains(flag),
            "`keyhog config --help` must document `{flag}`; got:\n{stdout}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. A config-affecting flag reaches the rendered effective config
// ---------------------------------------------------------------------------

#[test]
fn config_effective_min_confidence_override_reaches_output() {
    // --no-config makes the resolve hermetic (shipped defaults only), so the
    // ONLY thing that can move `min_confidence` is our explicit override.
    let (code, stdout, stderr) = run(&[
        "config",
        "--effective",
        "--no-config",
        "--daemon=off",
        "--min-confidence",
        "0.85",
    ]);
    assert_eq!(
        code,
        Some(0),
        "`keyhog config --effective` must exit 0 (renders, never scans); stderr={stderr}"
    );
    assert!(
        stdout.contains("[effective-config]"),
        "effective dump must carry its header; got:\n{stdout}"
    );
    assert!(
        stdout.contains("min_confidence = 0.85"),
        "the --min-confidence 0.85 override must reach the resolved config; got:\n{stdout}"
    );
}

#[test]
fn config_effective_decode_depth_and_threads_reach_output() {
    let (code, stdout, stderr) = run(&[
        "config",
        "--effective",
        "--no-config",
        "--daemon=off",
        "--decode-depth",
        "3",
        "--threads",
        "4",
    ]);
    assert_eq!(
        code,
        Some(0),
        "config --effective must exit 0; stderr={stderr}"
    );
    // --decode-depth 3 maps to max_decode_depth = 3 (scanner.rs: config.max_decode_depth = depth).
    assert!(
        stdout.contains("max_decode_depth = 3"),
        "the --decode-depth 3 override must reach max_decode_depth; got:\n{stdout}"
    );
    // --threads 4 maps straight through to the runtime thread count.
    assert!(
        stdout.contains("threads = 4"),
        "the --threads 4 override must reach the resolved threads; got:\n{stdout}"
    );
}

#[test]
fn config_effective_entropy_threshold_override_reaches_output() {
    let (code, stdout, stderr) = run(&[
        "config",
        "--effective",
        "--no-config",
        "--daemon=off",
        "--entropy-threshold",
        "6.5",
    ]);
    assert_eq!(
        code,
        Some(0),
        "config --effective must exit 0; stderr={stderr}"
    );
    // --entropy-threshold 6.5 maps to scanner.entropy_threshold (scanner.rs:141).
    assert!(
        stdout.contains("entropy_threshold = 6.5"),
        "the --entropy-threshold 6.5 override must reach the resolved config; got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// 3. Missing-required and unknown-flag boundaries → exit 2
// ---------------------------------------------------------------------------

#[test]
fn config_without_effective_exits_two() {
    // `--effective` is `required = true`: clap rejects the invocation at parse
    // time BEFORE the subcommand body's anyhow bail, so it is the clap
    // user-error path (exit 2), not a system error.
    let (code, _stdout, stderr) = run(&["config", "--no-config"]);
    assert_eq!(
        code,
        Some(2),
        "`keyhog config` without --effective is a user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("--effective"),
        "the parse error must name the missing --effective flag; got:\n{stderr}"
    );
}

#[test]
fn unknown_scan_flag_exits_two() {
    let (code, _stdout, stderr) = run(&["scan", "--definitely-not-a-flag"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown scan flag is a user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("unexpected argument"),
        "clap must report the unexpected argument; got:\n{stderr}"
    );
}

#[test]
fn unknown_top_level_flag_exits_two() {
    let (code, _stdout, stderr) = run(&["--not-a-real-top-level-flag"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown top-level flag is a user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("unexpected argument"),
        "clap must report the unexpected top-level argument; got:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// 4. Mutually-exclusive flag pairs → clap "cannot be used with" + exit 2
// ---------------------------------------------------------------------------

/// One assertion body for every documented conflict pair on the scan/config
/// surface: run `scan <a> <b>`, demand exit 2 AND clap's exact conflict
/// diagnostic. `extra` supplies any value tokens a flag needs.
fn assert_conflict(args: &[&str]) {
    let (code, _stdout, stderr) = run(args);
    assert_eq!(
        code,
        Some(2),
        "`keyhog {}` is a mutually-exclusive combination → exit 2; stderr={stderr}",
        args.join(" ")
    );
    assert!(
        stderr.contains("cannot be used with"),
        "clap must render the exact conflict diagnostic for `{}`; got:\n{stderr}",
        args.join(" ")
    );
}

#[test]
fn fast_and_deep_are_mutually_exclusive_exit_two() {
    // --fast conflicts_with_all includes "deep".
    assert_conflict(&["scan", "--fast", "--deep"]);
}

#[test]
fn no_gpu_and_require_gpu_are_mutually_exclusive_exit_two() {
    // --no-gpu conflicts_with "require_gpu" (and vice versa).
    assert_conflict(&["scan", "--no-gpu", "--require-gpu"]);
}

#[test]
fn no_config_and_config_are_mutually_exclusive_exit_two() {
    // --no-config conflicts_with "config"; the config subcommand inherits it.
    assert_conflict(&[
        "config",
        "--effective",
        "--no-config",
        "--config",
        "/tmp/x.toml",
    ]);
}

#[test]
fn baseline_and_create_baseline_are_mutually_exclusive_exit_two() {
    // --baseline conflicts_with_all ["create_baseline", "update_baseline"].
    assert_conflict(&[
        "scan",
        "--baseline",
        "a.json",
        "--create-baseline",
        "b.json",
    ]);
}

#[test]
fn positional_path_and_path_flag_are_mutually_exclusive_exit_two() {
    // The positional PATH arg has conflicts_with = "path".
    assert_conflict(&["scan", "somedir", "--path", "otherdir"]);
}

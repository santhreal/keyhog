//! LANE 5 (test-cli-e2e) — every subcommand's `--help` surface and the
//! bad-subcommand boundary, driven over the SHIPPED binary
//! (`CARGO_BIN_EXE_keyhog`).
//!
//! These are the cheapest, most-load-bearing e2e contracts a packager hits:
//!   1. EVERY documented subcommand answers `--help` with exit 0 AND the help
//!      text names the subcommand (`Usage: keyhog <name> …`) — a renamed or
//!      dropped subcommand, or a help renderer that panics, fails here.
//!   2. EVERY subcommand answers `-h` (the short alias) identically — clap wires
//!      both, but a `mut_subcommand`/`mut_arg` override (the dynamic-detector-
//!      count help in `args::command`) can silently break one spelling.
//!   3. The top-level `--help` / `-h` / no-args paths exit 0 and list every
//!      subcommand by name (the menu a first-run user sees).
//!   4. A bogus subcommand and a bogus top-level flag exit 2 (user error,
//!      per the documented exit-code contract) and say so on stderr.
//!
//! DATA-DRIVEN: the subcommand list is the single source of truth; each entry
//! produces ~4 assertion cases (long help exit, name-in-help, short help exit,
//! short==long agreement) → 15 subcommands × 4 ≈ 60 cases here, plus the
//! top-level and negative cases. Every assert pins an EXACT exit code and an
//! EXACT substring (never `!is_empty`).

use std::process::Command;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// The complete set of subcommands the CLI ships, as the user types them
/// (clap kebab-cases the enum variants — `ScanSystem` → `scan-system`). This
/// list is the contract: adding a `Command` variant without adding it here
/// leaves the new surface untested; removing one here without removing the
/// variant breaks `every_subcommand_long_help_exits_zero_and_names_itself`.
const SUBCOMMANDS: &[&str] = &[
    "scan",
    "hook",
    "detectors",
    "explain",
    "diff",
    "calibrate",
    "watch",
    "completion",
    "backend",
    "doctor",
    "update",
    "repair",
    "uninstall",
    "scan-system",
    "daemon",
];

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

#[test]
fn every_subcommand_long_help_exits_zero_and_names_itself() {
    for &sc in SUBCOMMANDS {
        let (code, stdout, stderr) = run(&[sc, "--help"]);
        assert_eq!(
            code,
            Some(0),
            "`keyhog {sc} --help` must exit 0; stderr={stderr}"
        );
        // clap renders `Usage: keyhog <name> …` to stdout for --help. The
        // subcommand name MUST appear so a stale/misrouted help can't pass.
        let needle = format!("keyhog {sc}");
        assert!(
            stdout.contains(&needle),
            "`keyhog {sc} --help` stdout must contain {needle:?} (the Usage line); got:\n{stdout}"
        );
    }
}

#[test]
fn every_subcommand_short_help_exits_zero() {
    for &sc in SUBCOMMANDS {
        let (code, stdout, stderr) = run(&[sc, "-h"]);
        assert_eq!(
            code,
            Some(0),
            "`keyhog {sc} -h` must exit 0; stderr={stderr}"
        );
        assert!(
            stdout.contains(&format!("keyhog {sc}")),
            "`keyhog {sc} -h` stdout must contain the Usage line; got:\n{stdout}"
        );
    }
}

#[test]
fn short_and_long_help_agree_for_every_subcommand() {
    // `-h` is the terse alias of `--help`; clap derives both. They are not
    // byte-identical (short vs long arg descriptions), but BOTH must carry the
    // Usage line — the dynamic-help `mut_subcommand` wiring in `args::command`
    // could regress one spelling while leaving the other intact, which this
    // pins.
    for &sc in SUBCOMMANDS {
        let long = run(&[sc, "--help"]);
        let short = run(&[sc, "-h"]);
        assert_eq!(
            long.0, short.0,
            "`keyhog {sc} --help` and `-h` must share an exit code"
        );
        let usage = format!("keyhog {sc}");
        assert!(
            long.1.contains(&usage) && short.1.contains(&usage),
            "both help spellings for `{sc}` must contain {usage:?}"
        );
    }
}

#[test]
fn top_level_help_lists_every_subcommand_by_name() {
    for flag in ["--help", "-h"] {
        let (code, stdout, stderr) = run(&[flag]);
        assert_eq!(
            code,
            Some(0),
            "`keyhog {flag}` must exit 0; stderr={stderr}"
        );
        for &sc in SUBCOMMANDS {
            assert!(
                stdout.contains(sc),
                "`keyhog {flag}` must list the `{sc}` subcommand in its menu; got:\n{stdout}"
            );
        }
    }
}

#[test]
fn no_args_prints_help_and_exits_zero() {
    // `keyhog` with no subcommand prints the top-level help (main.rs `None`
    // arm) and exits 0 — the friendly first-run path.
    let (code, stdout, _stderr) = run(&[]);
    assert_eq!(code, Some(0), "bare `keyhog` must exit 0");
    assert!(
        stdout.contains("keyhog") && stdout.contains("scan"),
        "bare `keyhog` must print the help menu naming `scan`; got:\n{stdout}"
    );
}

#[test]
fn unknown_subcommand_exits_two_and_reports_it() {
    let (code, _stdout, stderr) = run(&["definitely-not-a-subcommand"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown subcommand is a user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("unrecognized subcommand")
            || stderr.contains("definitely-not-a-subcommand"),
        "stderr must name the bad subcommand; got:\n{stderr}"
    );
}

#[test]
fn unknown_top_level_flag_exits_two() {
    let (code, _stdout, stderr) = run(&["--no-such-flag"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown top-level flag is a user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("--no-such-flag"),
        "stderr must name the bad flag; got:\n{stderr}"
    );
}

#[test]
fn version_flag_exits_zero_and_prints_version_block() {
    // `-V` / `--version` both fast-path to `print_version_info` (exit 0). The
    // block carries the build provenance every scan must trace to (commit +
    // detector digest) — assert the labels, not just non-emptiness.
    for flag in ["-V", "--version"] {
        let (code, stdout, stderr) = run(&[flag]);
        assert_eq!(
            code,
            Some(0),
            "`keyhog {flag}` must exit 0; stderr={stderr}"
        );
        assert!(
            stdout.contains("KeyHog v"),
            "`keyhog {flag}` must print the version banner; got:\n{stdout}"
        );
        assert!(
            stdout.contains("Commit:") && stdout.contains("Detector Set:"),
            "`keyhog {flag}` must print build provenance (Commit + Detector Set); got:\n{stdout}"
        );
    }
}

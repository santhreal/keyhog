//! `--version` / `--help` surface contract for the `keyhog` binary.
//!
//! These tests drive the SHIPPED binary as a real process through
//! `CARGO_BIN_EXE_keyhog` (the same pattern the sibling e2e suites use) and pin
//! CONCRETE values: the `--version` banner is checked against the cli crate's own
//! compiled-in `CARGO_PKG_VERSION` and the literal program name `KeyHog`; the
//! `--help` surface is checked to list every real subcommand declared in
//! `crates/cli/src/args.rs::Command`, to render the exact top-level `Usage:` line,
//! to carry the about tagline (both lines) and the generated `EXIT CODES:` block;
//! and the negative twins pin that an unknown flag / unknown subcommand is a clap
//! usage error (exit code 2) with a diagnostic on stderr.
//!
//! Every assertion is host-independent: none depend on an accelerator being
//! present. `--version` and `--help` never initialize hardware discovery (that is
//! gated behind the explicit `--full` flag), so these are pure, deterministic
//! string/exit-code contracts.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Run keyhog with `args`, returning (exit code, stdout, stderr).
fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(binary())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn keyhog {args:?}: {e}"));
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The exact, complete set of user-typed subcommand names declared on
/// `Command` in `crates/cli/src/args.rs` (clap kebab-cases the enum variants).
/// This is the source-of-truth list the top-level `--help` `Commands:` block must
/// enumerate. `help` (clap's auto-generated subcommand) is asserted separately.
const REAL_SUBCOMMANDS: &[&str] = &[
    "scan",
    "config",
    "hook",
    "detectors",
    "explain",
    "diff",
    "calibrate",
    "calibrate-autoroute",
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

/// Extract the first token of every entry line inside the `Commands:` block of a
/// `--help` stdout. The block begins at the `Commands:` header and ends at the
/// first blank line; each entry line is indented (`"  <name>   <desc>"`). Panics
/// if there is no `Commands:` header so a missing block is a hard failure, not a
/// silently-empty vector.
fn command_names(stdout: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_block = false;
    for line in stdout.lines() {
        if line.starts_with("Commands:") {
            in_block = true;
            continue;
        }
        if in_block {
            if line.trim().is_empty() {
                break;
            }
            if let Some(first) = line.split_whitespace().next() {
                names.push(first.to_string());
            }
        }
    }
    assert!(
        in_block,
        "--help output has no `Commands:` block; got:\n{stdout}"
    );
    names
}

// ---------------------------------------------------------------------------
// --version
// ---------------------------------------------------------------------------

/// `--version` exits 0 and its first line is byte-exactly
/// `KeyHog v{CARGO_PKG_VERSION}` — the program name `KeyHog` followed by the cli
/// crate's compiled-in package version (which inherits `version.workspace`).
#[test]
fn version_long_flag_prints_keyhog_banner_with_exact_pkg_version_exit0() {
    let (code, stdout, stderr) = run(&["--version"]);
    assert_eq!(code, Some(0), "--version must exit 0; stderr={stderr}");
    let first = stdout
        .lines()
        .next()
        .expect("--version must print a first line");
    let expected = format!("KeyHog v{}", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        first, expected,
        "--version line 1 must equal `{expected}`; got {first:?}"
    );
}

/// The short `-V` alias exits 0 and prints the SAME first-line banner as
/// `--version`, carrying the exact `CARGO_PKG_VERSION`. Guards the two flag
/// spellings from drifting to different versions.
#[test]
fn version_short_flag_matches_long_and_exact_pkg_version() {
    let (code, stdout, stderr) = run(&["-V"]);
    assert_eq!(code, Some(0), "-V must exit 0; stderr={stderr}");
    let first = stdout.lines().next().expect("-V must print a first line");
    let expected = format!("KeyHog v{}", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        first, expected,
        "-V line 1 must equal `{expected}`; got {first:?}"
    );
}

/// The very first whitespace-token of the `--version` banner is the program name
/// `KeyHog`, and the second token is `v{CARGO_PKG_VERSION}`. Pins the program
/// name and version as two distinct, exact tokens.
#[test]
fn version_banner_first_token_is_program_name_keyhog() {
    let (code, stdout, _e) = run(&["--version"]);
    assert_eq!(code, Some(0), "--version must exit 0");
    let first = stdout.lines().next().expect("first line");
    let mut tokens = first.split_whitespace();
    assert_eq!(
        tokens.next(),
        Some("KeyHog"),
        "banner token 0 must be the program name `KeyHog`; got line {first:?}"
    );
    let expected_ver = format!("v{}", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        tokens.next(),
        Some(expected_ver.as_str()),
        "banner token 1 must be `{expected_ver}`; got line {first:?}"
    );
}

/// `--version` writes its banner to STDOUT and leaves STDERR empty. A version
/// query is not an error, so nothing may leak onto the error stream.
#[test]
fn version_writes_to_stdout_not_stderr() {
    let (code, stdout, stderr) = run(&["--version"]);
    assert_eq!(code, Some(0), "--version must exit 0");
    assert!(
        stdout.starts_with("KeyHog v"),
        "banner must be on stdout; stdout={stdout:?}"
    );
    assert_eq!(
        stderr, "",
        "--version must not write anything to stderr; got {stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// --help
// ---------------------------------------------------------------------------

/// `--help` exits 0 and writes to STDOUT, not STDERR.
#[test]
fn help_long_flag_exits_zero_on_stdout() {
    let (code, stdout, stderr) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0; stderr={stderr}");
    assert_eq!(
        stderr, "",
        "--help must not write to stderr; got {stderr:?}"
    );
    assert!(
        stdout.contains("Usage: keyhog"),
        "--help stdout must contain a `Usage: keyhog` line; got:\n{stdout}"
    );
}

/// The top-level `Usage:` line is byte-exactly `Usage: keyhog [OPTIONS] [COMMAND]`
/// — binary name `keyhog`, options-then-optional-command shape.
#[test]
fn help_usage_line_is_exact() {
    let (code, stdout, _e) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0");
    let usage = stdout
        .lines()
        .find(|l| l.starts_with("Usage:"))
        .expect("--help must print a `Usage:` line");
    assert_eq!(
        usage, "Usage: keyhog [OPTIONS] [COMMAND]",
        "top-level usage line must be exact; got {usage:?}"
    );
}

/// The `Commands:` block enumerates EVERY real subcommand declared on `Command`
/// in `args.rs`, each as its own entry (kebab-cased, e.g. `scan-system`,
/// `calibrate-autoroute`). A dropped or renamed subcommand fails here.
#[test]
fn help_lists_every_real_subcommand() {
    let (code, stdout, _e) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0");
    let names = command_names(&stdout);
    for sub in REAL_SUBCOMMANDS {
        assert!(
            names.iter().any(|n| n == sub),
            "`--help` Commands block must list `{sub}`; listed: {names:?}"
        );
    }
}

/// clap's auto-generated `help` subcommand is present in the `Commands:` block,
/// and the block lists exactly the 17 real subcommands plus `help` — 18 entries,
/// no more, no fewer. A silently-added or hidden-then-unhidden subcommand fails.
#[test]
fn help_lists_exactly_real_subcommands_plus_help() {
    let (code, stdout, _e) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0");
    let names = command_names(&stdout);
    assert!(
        names.iter().any(|n| n == "help"),
        "Commands block must include clap's `help` subcommand; listed: {names:?}"
    );
    assert_eq!(
        names.len(),
        REAL_SUBCOMMANDS.len() + 1,
        "Commands block must list exactly {} real subcommands + `help`; listed {}: {names:?}",
        REAL_SUBCOMMANDS.len(),
        names.len()
    );
}

/// The `scan` entry carries its exact one-line description from the `Command::Scan`
/// doc-comment. Pins that the listing is the real help text, not a placeholder.
#[test]
fn help_scan_entry_has_exact_description() {
    let (code, stdout, _e) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0");
    assert!(
        stdout.contains("Scan files, directories, or repositories for secrets"),
        "--help must carry the exact scan description; got:\n{stdout}"
    );
}

/// The two-line about tagline (from `#[command(about = ...)]`) is rendered at the
/// top of `--help`, both lines byte-exact.
#[test]
fn help_carries_about_tagline_two_lines() {
    let (code, stdout, _e) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0");
    assert!(
        stdout.contains("KeyHog: The developer-first secret scanner."),
        "--help must carry the about line 1; got:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "Find leaked credentials in your code before hackers do. Fast, accurate, and verifying."
        ),
        "--help must carry the about line 2; got:\n{stdout}"
    );
}

/// The `Options:` surface documents both the `-V, --version` and `-h, --help`
/// flags — the two flags this suite exercises must be self-described in help.
#[test]
fn help_documents_version_and_help_option_flags() {
    let (code, stdout, _e) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0");
    assert!(
        stdout.contains("-V, --version"),
        "--help Options must document `-V, --version`; got:\n{stdout}"
    );
    assert!(
        stdout.contains("-h, --help"),
        "--help Options must document `-h, --help`; got:\n{stdout}"
    );
}

/// The generated `EXIT CODES:` block (from `exit_codes::help()`) is appended to
/// `--help`, with the exact success row `  0   Success (no secrets found)`.
#[test]
fn help_carries_exit_codes_block_with_success_row() {
    let (code, stdout, _e) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0");
    assert!(
        stdout.contains("EXIT CODES:"),
        "--help must carry the EXIT CODES block; got:\n{stdout}"
    );
    assert!(
        stdout.contains("  0   Success (no secrets found)"),
        "--help EXIT CODES must contain the exact code-0 row; got:\n{stdout}"
    );
    // The user-error row must state exit 2 — the same code the negative-twin
    // tests below assert for a bad flag / bad subcommand.
    assert!(
        stdout.contains("  2   User error"),
        "--help EXIT CODES must document code 2 as User error; got:\n{stdout}"
    );
}

/// The short `-h` produces the same `Commands:` listing as `--help`: identical
/// command-name set and identical count, at exit 0. The two help spellings must
/// enumerate the same surface.
#[test]
fn short_h_lists_same_commands_as_long_help() {
    let (code_long, out_long, _e1) = run(&["--help"]);
    let (code_short, out_short, _e2) = run(&["-h"]);
    assert_eq!(code_long, Some(0), "--help must exit 0");
    assert_eq!(code_short, Some(0), "-h must exit 0");
    assert_eq!(
        command_names(&out_short),
        command_names(&out_long),
        "-h and --help must enumerate the identical command set"
    );
}

// ---------------------------------------------------------------------------
// negative twins — usage errors
// ---------------------------------------------------------------------------

/// An unknown top-level flag is a clap usage error: exit code 2, with an
/// `unexpected argument` diagnostic AND a `Usage: keyhog` line on STDERR (not
/// stdout). Adversarial negative twin of the `--help` surface.
#[test]
fn unknown_flag_exits_two_with_usage_error_on_stderr() {
    let (code, stdout, stderr) = run(&["--definitely-not-a-flag"]);
    assert_eq!(
        code,
        Some(2),
        "unknown flag must exit 2 (user error); stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("unexpected argument"),
        "stderr must name the unexpected argument; got:\n{stderr}"
    );
    assert!(
        stderr.contains("Usage: keyhog"),
        "clap error must surface a `Usage: keyhog` line on stderr; got:\n{stderr}"
    );
}

/// An unrecognized subcommand is a clap usage error: exit code 2 with an
/// `unrecognized subcommand` diagnostic on STDERR. Negative twin of the
/// subcommand listing.
#[test]
fn unknown_subcommand_exits_two_with_unrecognized_diagnostic() {
    let (code, stdout, stderr) = run(&["definitely-not-a-subcommand"]);
    assert_eq!(
        code,
        Some(2),
        "unknown subcommand must exit 2 (user error); stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("unrecognized subcommand"),
        "clap error must state `unrecognized subcommand`; got:\n{stderr}"
    );
    assert!(
        stderr.contains("Usage: keyhog"),
        "clap error must surface a `Usage: keyhog` line on stderr; got:\n{stderr}"
    );
}

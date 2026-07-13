//! e2e regression suite for keyhog's auxiliary (non-scan) subcommands.
//!
//! These lock the operator-visible *contracts* of the small utility commands
//! that surround the scanner, shell completion, `config --effective`,
//! `--version`, `--help`, and the parse-error exit code, against concrete,
//! byte-exact expectations. Each assertion pins a specific value (an exact
//! first line, an exact key, an exact exit code, an exact command set) so a
//! silent regression in any of them fails the suite loudly rather than being
//! masked by a `!is_empty()` smoke check.
//!
//! The binary is invoked through `CARGO_BIN_EXE_keyhog` (cargo points this at
//! the freshly built `keyhog` binary for this crate), the same real-process
//! pattern every other e2e file here uses. `assert_cmd` is intentionally NOT a
//! dev-dependency of this crate, so we drive `std::process::Command` directly.

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

/// The exact set of subcommands keyhog exposes. `help` is clap's auto-generated
/// subcommand; the other 17 are the `args::Command` enum variants, rendered in
/// clap's kebab-case (`calibrate-autoroute`, `scan-system`).
const EXPECTED_SUBCOMMANDS: &[&str] = &[
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
    "help",
];

// ---------------------------------------------------------------------------
// completion <shell>, exact shell-specific first line (clap_complete 4.6)
// ---------------------------------------------------------------------------

/// `keyhog completion bash` emits a bash script whose first line is the
/// completion-function definition `_keyhog() {` (clap_complete's bash template).
#[test]
fn completion_bash_first_line_is_function_definition() {
    let (code, stdout, stderr) = run(&["completion", "bash"]);
    assert_eq!(
        code,
        Some(0),
        "completion bash must exit 0; stderr={stderr}"
    );
    let first = stdout
        .lines()
        .next()
        .expect("bash completion has a first line");
    assert_eq!(
        first, "_keyhog() {",
        "bash completion must open with the `_keyhog()` function; got first line: {first:?}"
    );
}

/// `keyhog completion zsh` emits a zsh script whose first line is the exact
/// `#compdef keyhog` directive zsh's completion loader requires.
#[test]
fn completion_zsh_first_line_is_compdef() {
    let (code, stdout, stderr) = run(&["completion", "zsh"]);
    assert_eq!(code, Some(0), "completion zsh must exit 0; stderr={stderr}");
    let first = stdout
        .lines()
        .next()
        .expect("zsh completion has a first line");
    assert_eq!(
        first, "#compdef keyhog",
        "zsh completion must open with `#compdef keyhog`; got first line: {first:?}"
    );
}

/// `keyhog completion fish` emits a fish script whose first line is the exact
/// optspec-helper comment clap_complete generates for a command with
/// subcommands.
#[test]
fn completion_fish_first_line_is_optspec_comment() {
    let (code, stdout, stderr) = run(&["completion", "fish"]);
    assert_eq!(
        code,
        Some(0),
        "completion fish must exit 0; stderr={stderr}"
    );
    let first = stdout
        .lines()
        .next()
        .expect("fish completion has a first line");
    assert_eq!(
        first,
        "# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.",
        "fish completion must open with the optspec comment; got first line: {first:?}"
    );
}

/// `keyhog completion` with no shell argument is a usage error (the `shell`
/// positional is required) → exit 2, and stderr names the missing argument.
#[test]
fn completion_missing_shell_arg_is_usage_error() {
    let (code, _stdout, stderr) = run(&["completion"]);
    assert_eq!(
        code,
        Some(2),
        "completion with no shell must be a usage error (exit 2); stderr={stderr}"
    );
    assert!(
        stderr.contains("<SHELL>") || stderr.contains("required"),
        "stderr must flag the missing required shell arg; got:\n{stderr}"
    );
}

/// `keyhog completion tcsh` (an unsupported shell) is a usage error → exit 2,
/// and stderr reports the invalid value.
#[test]
fn completion_unknown_shell_is_usage_error() {
    let (code, _stdout, stderr) = run(&["completion", "tcsh"]);
    assert_eq!(
        code,
        Some(2),
        "an unsupported shell is a usage error (exit 2); stderr={stderr}"
    );
    assert!(
        stderr.contains("invalid value") && stderr.contains("tcsh"),
        "stderr must reject `tcsh` as an invalid value; got:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// --version, exact semver + git-hash shape
// ---------------------------------------------------------------------------

/// `keyhog --version` line 1 is exactly `KeyHog v<semver>`, where the semver is
/// the crate's compiled `CARGO_PKG_VERSION` and has an `X.Y.Z` shape.
#[test]
fn version_first_line_is_keyhog_semver() {
    let (code, stdout, stderr) = run(&["--version"]);
    assert_eq!(code, Some(0), "--version must exit 0; stderr={stderr}");
    let first = stdout.lines().next().expect("--version has a first line");
    let expected = format!("KeyHog v{}", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        first, expected,
        "--version line 1 must be `KeyHog v<CARGO_PKG_VERSION>`; got: {first:?}"
    );

    // Enforce the semver *shape* (three dot-separated numeric components) so a
    // non-semver version string (e.g. a date, or a missing patch) is caught.
    let ver = first
        .strip_prefix("KeyHog v")
        .expect("first line starts with `KeyHog v`");
    let parts: Vec<&str> = ver.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "version must have exactly 3 dot-separated components (X.Y.Z); got {ver:?}"
    );
    for (idx, part) in parts.iter().enumerate() {
        assert!(
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
            "version component {idx} must be a non-empty run of ASCII digits; got {part:?} in {ver:?}"
        );
    }
}

/// `keyhog --version` line 2 is `Commit: <hash>`, where `<hash>` is either the
/// full 40-hex-char git SHA the binary was stamped with, or the literal
/// `unknown` for a build with no reachable `.git` tree.
#[test]
fn version_commit_line_is_full_hash_or_unknown() {
    let (code, stdout, _stderr) = run(&["--version"]);
    assert_eq!(code, Some(0), "--version must exit 0");
    let commit_line = stdout.lines().nth(1).expect("--version has a second line");
    let hash = commit_line
        .strip_prefix("Commit: ")
        .unwrap_or_else(|| panic!("line 2 must start with `Commit: `; got: {commit_line:?}"));
    let is_full_sha = hash.len() == 40 && hash.bytes().all(|b| b.is_ascii_hexdigit());
    assert!(
        is_full_sha || hash == "unknown",
        "commit hash must be a 40-char hex SHA or `unknown`; got: {hash:?}"
    );
}

/// `keyhog --version` includes a `Build Target: <arch>-<os>` line whose value
/// is exactly this build's `ARCH-OS`, matching `std::env::consts`.
#[test]
fn version_build_target_matches_arch_and_os() {
    let (code, stdout, _stderr) = run(&["--version"]);
    assert_eq!(code, Some(0), "--version must exit 0");
    let expected = format!(
        "Build Target: {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    assert!(
        stdout.lines().any(|l| l == expected),
        "--version must print `{expected}`; got:\n{stdout}"
    );
}

/// The short `-V` flag is an exact alias of `--version`: identical first line.
#[test]
fn version_short_flag_matches_long_flag_first_line() {
    let (code_short, out_short, _e1) = run(&["-V"]);
    let (code_long, out_long, _e2) = run(&["--version"]);
    assert_eq!(code_short, Some(0), "-V must exit 0");
    assert_eq!(code_long, Some(0), "--version must exit 0");
    assert_eq!(
        out_short.lines().next(),
        out_long.lines().next(),
        "-V and --version must print the same first (version) line"
    );
    assert_eq!(
        out_short.lines().next(),
        Some(format!("KeyHog v{}", env!("CARGO_PKG_VERSION")).as_str()),
        "-V first line must also be `KeyHog v<CARGO_PKG_VERSION>`"
    );
}

// ---------------------------------------------------------------------------
// --help, exact subcommand set
// ---------------------------------------------------------------------------

/// `keyhog --help` lists exactly the expected subcommand set under `Commands:`
///: no more, no fewer. Parsed by taking the first token of every command entry
/// (a line indented by exactly two spaces) in the Commands block.
#[test]
fn help_lists_exact_subcommand_set() {
    let (code, stdout, stderr) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0; stderr={stderr}");

    let mut in_commands = false;
    let mut names: Vec<String> = Vec::new();
    for line in stdout.lines() {
        if line.starts_with("Commands:") {
            in_commands = true;
            continue;
        }
        if in_commands {
            // The Commands block ends at the first blank line before the next
            // section (e.g. `Options:`).
            if line.trim().is_empty() {
                break;
            }
            // Command entries are indented by EXACTLY two spaces; wrapped
            // description continuation lines are indented further, so requiring
            // a non-space third character isolates the command names.
            if line.starts_with("  ") && !line.starts_with("   ") {
                if let Some(tok) = line.trim_start().split_whitespace().next() {
                    names.push(tok.to_string());
                }
            }
        }
    }

    let mut got = names.clone();
    got.sort();
    got.dedup();
    let mut expected: Vec<String> = EXPECTED_SUBCOMMANDS.iter().map(|s| s.to_string()).collect();
    expected.sort();
    assert_eq!(
        got, expected,
        "`--help` Commands block must list exactly the expected subcommand set;\nraw parsed: {names:?}\nfull help:\n{stdout}"
    );
}

/// The multi-word subcommands are rendered in kebab-case (clap's default), not
/// camelCase or PascalCase (the exact strings a user must type).
#[test]
fn help_multiword_subcommands_are_kebab_case() {
    let (code, stdout, _stderr) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0");
    // Positive: the kebab-case command lines (two-space indent, trailing space
    // before the aligned description) are present.
    assert!(
        stdout.contains("\n  calibrate-autoroute "),
        "help must list `calibrate-autoroute`; got:\n{stdout}"
    );
    assert!(
        stdout.contains("\n  scan-system "),
        "help must list `scan-system`; got:\n{stdout}"
    );
    // Negative twin: the camel/Pascal forms must NOT appear.
    for bad in [
        "calibrateAutoroute",
        "CalibrateAutoroute",
        "scanSystem",
        "ScanSystem",
    ] {
        assert!(
            !stdout.contains(bad),
            "help must not contain the non-kebab form {bad:?}; got:\n{stdout}"
        );
    }
}

// ---------------------------------------------------------------------------
// config, requires --effective; prints the effective-config keys
// ---------------------------------------------------------------------------

/// `keyhog config` without `--effective` is a user error → exit 2, with the
/// exact remediation guidance on stderr.
#[test]
fn config_without_effective_is_user_error_with_guidance() {
    let (code, _stdout, stderr) = run(&["config"]);
    assert_eq!(
        code,
        Some(2),
        "`config` without --effective is a user error (exit 2); stderr={stderr}"
    );
    // `--effective` is a clap-`required` argument, so clap rejects the missing
    // value with its standard diagnostic (which names the flag) before the
    // subcommand body runs (assert that exact behavior).
    assert!(
        stderr.contains("required arguments were not provided") && stderr.contains("--effective"),
        "stderr must state --effective is required; got:\n{stderr}"
    );
    assert!(
        stderr.contains("keyhog config --effective"),
        "stderr must include the fix invocation (usage line); got:\n{stderr}"
    );
}

/// `keyhog config --effective` prints the effective-config table: the exact
/// `[effective-config]` header first, followed by the documented `key = value`
/// lines. Asserts the header and a representative set of exact key names.
#[test]
fn config_effective_prints_header_and_expected_keys() {
    let (code, stdout, stderr) = run(&["config", "--effective"]);
    assert_eq!(
        code,
        Some(0),
        "`config --effective` must exit 0; stderr={stderr}"
    );
    let first = stdout
        .lines()
        .next()
        .expect("config output has a first line");
    assert_eq!(
        first, "[effective-config]",
        "config --effective must open with the `[effective-config]` header; got: {first:?}"
    );

    // Every one of these keys is emitted unconditionally by
    // `render_effective_config`; assert each exact `key = ` prefix appears on
    // its own line.
    let required_keys = [
        "backend",
        "batch_pipeline",
        "threads",
        "reader_threads",
        "fused_batch",
        "gpu",
        "autoroute_gpu",
        "min_confidence",
        "ml_enabled",
        "ml_weight",
        "entropy_enabled",
        "entropy_threshold",
        "max_decode_depth",
        "max_decode_bytes",
        "regex_dfa_limit",
        "gpu_batch_input_limit",
        "max_file_size",
        "no_default_excludes",
        "exclude_paths",
        "incremental",
        "incremental_cache",
        "limit_stdin_bytes",
    ];
    for key in required_keys {
        let prefix = format!("{key} = ");
        assert!(
            stdout.lines().any(|l| l.starts_with(&prefix)),
            "config --effective must emit a `{prefix}...` line; got:\n{stdout}"
        );
    }
}

/// `keyhog config --effective` with no flags shows the concrete default values
/// for the flag-free knobs: no excludes, non-incremental.
#[test]
fn config_effective_defaults_have_exact_values() {
    let (code, stdout, stderr) = run(&["config", "--effective"]);
    assert_eq!(
        code,
        Some(0),
        "config --effective must exit 0; stderr={stderr}"
    );
    assert!(
        stdout.lines().any(|l| l == "exclude_paths = 0"),
        "default exclude_paths must be exactly 0; got:\n{stdout}"
    );
    assert!(
        stdout.lines().any(|l| l == "incremental = false"),
        "default incremental must be exactly false; got:\n{stdout}"
    );
    assert!(
        stdout.lines().any(|l| l == "no_default_excludes = false"),
        "default no_default_excludes must be exactly false; got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// unknown subcommand, usage-error exit code
// ---------------------------------------------------------------------------

/// An unrecognized subcommand is a usage error: exit code 2, with clap naming
/// the offending token on stderr.
#[test]
fn unknown_subcommand_exits_two() {
    let (code, _stdout, stderr) = run(&["frobnicate-the-widgets"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown subcommand must exit 2 (EXIT_USER_ERROR); stderr={stderr}"
    );
    assert!(
        stderr.contains("unrecognized subcommand") && stderr.contains("frobnicate-the-widgets"),
        "stderr must report the unrecognized subcommand by name; got:\n{stderr}"
    );
}

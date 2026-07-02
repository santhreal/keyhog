//! Version / build-provenance coherence contract for the `keyhog` binary.
//!
//! Every assertion here pins a CONCRETE value: the `--version` banner is checked
//! against the crate's own `CARGO_PKG_VERSION`, the git hash / detector digest /
//! ML-model version are checked against the exact library accessors that produce
//! them (`keyhog_core::git_hash`, `keyhog_core::detector_digest`,
//! `keyhog_core::embedded_detector_count`, `keyhog_scanner::ml_scorer::model_version`),
//! and the build-target line is checked against `std::env::consts`. The binary is
//! driven as a real process through `CARGO_BIN_EXE_keyhog` — the same pattern the
//! sibling e2e suites use — so a drift between what the binary prints and what the
//! linked libraries report fails loudly instead of hiding behind a smoke check.
//!
//! Because the test crate links the SAME workspace `keyhog-core` / `keyhog-scanner`
//! rlibs that the binary embeds (identical build, identical stamped build.rs env
//! vars), these cross-checks are exact-equality, not shape approximations.

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

/// Return the `Usage:` line from a `--help` stdout, split into whitespace tokens.
/// Token 0 is always `"Usage:"`; token 1 is the binary name; token 2 (if present)
/// is the subcommand. Panics if no usage line is found so a missing usage block is
/// a hard failure, not a silently-empty vector.
fn usage_tokens(stdout: &str) -> Vec<String> {
    let line = stdout
        .lines()
        .find(|l| l.starts_with("Usage:"))
        .unwrap_or_else(|| panic!("help output has no `Usage:` line; got:\n{stdout}"));
    line.split_whitespace().map(|t| t.to_string()).collect()
}

// ---------------------------------------------------------------------------
// --version ↔ CARGO_PKG_VERSION
// ---------------------------------------------------------------------------

/// The first `--version` line is byte-exactly `KeyHog v{CARGO_PKG_VERSION}`.
/// `CARGO_PKG_VERSION` is the cli crate's compiled-in package version (which
/// inherits `version.workspace = true`), so this is the authoritative equality
/// between the shipped banner and the Cargo manifest.
#[test]
fn version_first_line_equals_cargo_pkg_version() {
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

/// The reported version is a strict three-component numeric semver: exactly
/// `X.Y.Z`, every component a non-empty run of ASCII digits, and NO pre-release
/// (`-`) or build-metadata (`+`) suffix. A date-stamp, a two-part `X.Y`, or a
/// `1.2.3-rc1` would all fail here.
#[test]
fn version_string_is_strict_numeric_semver() {
    let ver = env!("CARGO_PKG_VERSION");
    assert!(
        !ver.contains('-'),
        "version must carry no pre-release suffix; got {ver:?}"
    );
    assert!(
        !ver.contains('+'),
        "version must carry no build-metadata suffix; got {ver:?}"
    );
    let parts: Vec<&str> = ver.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "version must have exactly 3 dot-separated components; got {ver:?}"
    );
    for (idx, part) in parts.iter().enumerate() {
        assert!(
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
            "version component {idx} must be a non-empty ASCII-digit run; got {part:?} in {ver:?}"
        );
    }
    // The binary must be reporting this same string, not a divergent one.
    let (_, stdout, _) = run(&["--version"]);
    let first = stdout.lines().next().expect("first line");
    let printed = first
        .strip_prefix("KeyHog v")
        .expect("first line begins with `KeyHog v`");
    assert_eq!(
        printed, ver,
        "binary-reported semver must equal CARGO_PKG_VERSION"
    );
}

/// `-V` and `--version` are exact aliases: identical exit code AND byte-identical
/// stdout. This guards the two flag spellings from drifting to different banners.
#[test]
fn short_and_long_version_flags_are_byte_identical() {
    let (code_long, out_long, _e1) = run(&["--version"]);
    let (code_short, out_short, _e2) = run(&["-V"]);
    assert_eq!(code_long, Some(0), "--version must exit 0");
    assert_eq!(code_short, Some(0), "-V must exit 0");
    assert_eq!(
        out_short, out_long,
        "-V and --version must print byte-identical stdout"
    );
}

// ---------------------------------------------------------------------------
// build-provenance lines ↔ library accessors
// ---------------------------------------------------------------------------

/// Line 2 is exactly `Commit: {keyhog_core::git_hash()}` — the build.rs-stamped
/// git SHA (or the literal `unknown` for a no-.git build), verified against the
/// SAME accessor the binary formats from.
#[test]
fn version_commit_line_matches_core_git_hash() {
    let (code, stdout, _e) = run(&["--version"]);
    assert_eq!(code, Some(0), "--version must exit 0");
    let commit_line = stdout
        .lines()
        .nth(1)
        .expect("--version must print a second line");
    let expected = format!("Commit: {}", keyhog_core::git_hash());
    assert_eq!(
        commit_line, expected,
        "line 2 must equal `{expected}`; got {commit_line:?}"
    );
}

/// The `Detector Set:` line is byte-exactly
/// `Detector Set: {count} ({digest})`, where `count` is
/// `keyhog_core::embedded_detector_count()` and `digest` is
/// `keyhog_core::detector_digest()` (`<count>-<16-hex>`). This is the strongest
/// coherence check: the running binary's compiled corpus must match the corpus
/// the linked core rlib reports, to the exact digest.
#[test]
fn version_detector_set_line_matches_core_count_and_digest() {
    let (code, stdout, _e) = run(&["--version"]);
    assert_eq!(code, Some(0), "--version must exit 0");
    let line = stdout
        .lines()
        .find(|l| l.starts_with("Detector Set:"))
        .expect("--version must print a `Detector Set:` line");
    let count = keyhog_core::embedded_detector_count();
    let digest = keyhog_core::detector_digest();
    let expected = format!("Detector Set: {count} ({digest})");
    assert_eq!(
        line, expected,
        "detector-set line must equal `{expected}`; got {line:?}"
    );
    // The digest is defined as `<count>-<hash>`, so its count prefix must agree
    // with the standalone count — a defensive cross-check of the two sources.
    let digest_prefix = format!("{count}-");
    assert!(
        digest.starts_with(&digest_prefix),
        "digest {digest:?} must begin with the detector count `{digest_prefix}`"
    );
}

/// The `Build Target:` line is byte-exactly `Build Target: {ARCH}-{OS}`, using
/// the host's compile-time `std::env::consts`. On x86-64 Linux this is
/// `Build Target: x86_64-linux`.
#[test]
fn version_build_target_line_matches_host_arch_os() {
    let (code, stdout, _e) = run(&["--version"]);
    assert_eq!(code, Some(0), "--version must exit 0");
    let expected = format!(
        "Build Target: {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    let line = stdout
        .lines()
        .find(|l| l.starts_with("Build Target:"))
        .expect("--version must print a `Build Target:` line");
    assert_eq!(
        line, expected,
        "build-target line must equal `{expected}`; got {line:?}"
    );
}

/// The `ML Model Version:` line is byte-exactly
/// `ML Model Version: {keyhog_scanner::ml_scorer::model_version()}`, checked
/// against the SAME embedded-model accessor the binary formats from.
#[test]
fn version_ml_model_version_line_matches_scanner_accessor() {
    let (code, stdout, _e) = run(&["--version"]);
    assert_eq!(code, Some(0), "--version must exit 0");
    let expected = format!(
        "ML Model Version: {}",
        keyhog_scanner::ml_scorer::model_version()
    );
    let line = stdout
        .lines()
        .find(|l| l.starts_with("ML Model Version:"))
        .expect("--version must print an `ML Model Version:` line");
    assert_eq!(
        line, expected,
        "ml-model-version line must equal `{expected}`; got {line:?}"
    );
}

/// Plain `--version` prints EXACTLY six provenance lines, in order: banner,
/// Commit, Detector Set, Build Target, ML Model Version, ML Model Card. A drift
/// in count (an added or dropped line) fails here.
#[test]
fn plain_version_prints_exactly_six_lines() {
    let (code, stdout, _e) = run(&["--version"]);
    assert_eq!(code, Some(0), "--version must exit 0");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        6,
        "plain --version must print exactly 6 lines; got {}:\n{stdout}",
        lines.len()
    );
    let prefixes = [
        "KeyHog v",
        "Commit: ",
        "Detector Set: ",
        "Build Target: ",
        "ML Model Version: ",
        "ML Model Card: ",
    ];
    for (idx, prefix) in prefixes.iter().enumerate() {
        assert!(
            lines[idx].starts_with(prefix),
            "line {idx} must start with {prefix:?}; got {:?}",
            lines[idx]
        );
    }
}

/// `--version --full` is a strict superset of plain `--version`: its first six
/// lines are byte-identical to the plain banner, and it appends at least the
/// GPU + SIMD hardware lines (so strictly more than six total).
#[test]
fn full_version_prefix_matches_plain_and_adds_hardware_lines() {
    let (code_plain, out_plain, _e1) = run(&["--version"]);
    let (code_full, out_full, _e2) = run(&["--version", "--full"]);
    assert_eq!(code_plain, Some(0), "--version must exit 0");
    assert_eq!(code_full, Some(0), "--version --full must exit 0");

    let plain_lines: Vec<&str> = out_plain.lines().collect();
    let full_lines: Vec<&str> = out_full.lines().collect();
    assert_eq!(plain_lines.len(), 6, "plain --version must be 6 lines");
    assert!(
        full_lines.len() > 6,
        "--full must append hardware lines beyond the 6 core lines; got {}",
        full_lines.len()
    );
    assert_eq!(
        &full_lines[..6],
        &plain_lines[..],
        "--full first 6 lines must be byte-identical to plain --version"
    );
    // The GPU + SIMD hardware lines are always emitted under --full regardless
    // of what hardware is present.
    assert!(
        out_full.contains("GPU Acceleration:"),
        "--full must print a `GPU Acceleration:` line; got:\n{out_full}"
    );
    assert!(
        out_full.contains("SIMD Regex:"),
        "--full must print a `SIMD Regex:` line; got:\n{out_full}"
    );
}

/// `--version` is deterministic: two independent invocations produce byte-identical
/// stdout. The provenance banner must not depend on wall-clock, PID, or env.
#[test]
fn version_output_is_deterministic_across_runs() {
    let (_, out_a, _) = run(&["--version"]);
    let (_, out_b, _) = run(&["--version"]);
    assert_eq!(
        out_a, out_b,
        "two --version runs must produce byte-identical stdout"
    );
}

/// A `--version` flag ANYWHERE on the line short-circuits the subcommand: the
/// binary scans `args_os` for `-V`/`--version` before dispatch, so
/// `keyhog detectors --version` prints the version banner and exits 0 instead of
/// running the `detectors` subcommand. This pins that documented fast-path.
#[test]
fn version_flag_short_circuits_subcommand() {
    let (code, stdout, stderr) = run(&["detectors", "--version"]);
    assert_eq!(
        code,
        Some(0),
        "`detectors --version` must exit 0 via the version fast-path; stderr={stderr}"
    );
    let first = stdout.lines().next().expect("first line");
    let expected = format!("KeyHog v{}", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        first, expected,
        "`detectors --version` must print the version banner, not detector output"
    );
}

// ---------------------------------------------------------------------------
// --help ↔ binary-name coherence
// ---------------------------------------------------------------------------

/// `keyhog --help` exits 0 and its `Usage:` line names the binary exactly
/// `keyhog` (token 1). Also asserts the human-facing about tagline is present.
#[test]
fn top_level_help_usage_names_binary_keyhog() {
    let (code, stdout, stderr) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0; stderr={stderr}");
    let tokens = usage_tokens(&stdout);
    assert_eq!(tokens[0], "Usage:", "usage line must start with `Usage:`");
    assert_eq!(
        tokens[1], "keyhog",
        "top-level usage must name the binary `keyhog`; usage tokens: {tokens:?}"
    );
    assert!(
        stdout.contains("KeyHog: The developer-first secret scanner."),
        "--help must carry the about tagline; got:\n{stdout}"
    );
}

/// `--help` and the short `-h` produce byte-identical stdout at exit 0 — the two
/// help spellings must never diverge.
#[test]
fn long_help_and_short_h_are_byte_identical() {
    let (code_long, out_long, _e1) = run(&["--help"]);
    let (code_short, out_short, _e2) = run(&["-h"]);
    assert_eq!(code_long, Some(0), "--help must exit 0");
    assert_eq!(code_short, Some(0), "-h must exit 0");
    assert_eq!(
        out_short, out_long,
        "-h and --help must print byte-identical stdout"
    );
}

/// Every subcommand's `--help` usage line agrees with the top-level binary name:
/// token 1 is `keyhog` and token 2 is the exact (kebab-cased) subcommand name a
/// user types. Covers a representative set including the multi-word
/// `scan-system` and `calibrate-autoroute`.
#[test]
fn subcommand_help_usage_agrees_on_binary_and_subcommand_name() {
    let subcommands = [
        "scan",
        "config",
        "detectors",
        "explain",
        "diff",
        "backend",
        "doctor",
        "scan-system",
        "calibrate-autoroute",
    ];
    for sub in subcommands {
        let (code, stdout, stderr) = run(&[sub, "--help"]);
        assert_eq!(code, Some(0), "`{sub} --help` must exit 0; stderr={stderr}");
        let tokens = usage_tokens(&stdout);
        assert_eq!(
            tokens[1], "keyhog",
            "`{sub} --help` usage must name binary `keyhog`; tokens: {tokens:?}"
        );
        assert_eq!(
            tokens[2], sub,
            "`{sub} --help` usage second token must be the subcommand `{sub}`; tokens: {tokens:?}"
        );
    }
}

/// An unrecognized subcommand is a clap usage error: exit code 2 with a usage
/// line on stderr that names the `keyhog` binary. Adversarial negative twin of
/// the help-coherence checks.
#[test]
fn unknown_subcommand_errors_exit_two_and_names_keyhog() {
    let (code, stdout, stderr) = run(&["definitely-not-a-subcommand"]);
    assert_eq!(
        code,
        Some(2),
        "unknown subcommand must exit 2 (user error); stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("Usage: keyhog"),
        "clap error must surface a `Usage: keyhog` line on stderr; got:\n{stderr}"
    );
}

//! End-to-end CLI contract for the top-level surface plus the `daemon`
//! start/stop/status subcommand tree, driven through the REAL shipped binary
//! (`env!("CARGO_BIN_EXE_keyhog")`) (the exact path an operator hits).
//!
//! Every assertion pins a CONCRETE value: an exact stdout line, an exact exit
//! code, a specific error phrase, or a cross-checked count/contract sourced
//! from the same public API the binary prints from
//! (`keyhog_core::embedded_detector_count`, `keyhog::exit_codes::help`). No
//! `is_empty()`/`len()>0`-only assertions.
//!
//! Coverage: positive (version/help/doctor), negative-twin (plain vs `--full`),
//! boundary (`--full` requires `--version`), adversarial (unknown
//! subcommand/flag), and the daemon admin surface with no daemon running.

use std::process::{Command, Output};

/// Run the shipped binary with color disabled (so string assertions see plain
/// bytes regardless of TTY) and capture its output.
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("CLICOLOR_FORCE")
        .output()
        .expect("spawn keyhog binary")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ── Version surface ──────────────────────────────────────────────────────

#[test]
fn version_long_first_line_is_exact_crate_version() {
    let out = run(&["--version"]);
    assert_eq!(out.status.code(), Some(0), "--version must exit 0");
    let stdout = stdout_of(&out);
    let first = stdout.lines().next().expect("version output has a line");
    let expected = format!("KeyHog v{}", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        first, expected,
        "--version first line must be the exact crate version banner"
    );
}

#[test]
fn short_v_flag_produces_identical_version_output() {
    let long = run(&["--version"]);
    let short = run(&["-V"]);
    assert_eq!(long.status.code(), Some(0));
    assert_eq!(short.status.code(), Some(0));
    let long_stdout = stdout_of(&long);
    let short_stdout = stdout_of(&short);
    assert_eq!(
        short_stdout, long_stdout,
        "`-V` and `--version` must print byte-identical output"
    );
}

#[test]
fn version_build_target_line_matches_this_host() {
    let out = run(&["--version"]);
    let stdout = stdout_of(&out);
    let expected = format!(
        "Build Target: {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    assert!(
        stdout.lines().any(|l| l == expected),
        "version output must carry the exact `{expected}` line; got:\n{stdout}"
    );
}

#[test]
fn version_detector_set_count_matches_embedded_corpus() {
    let out = run(&["--version"]);
    let stdout = stdout_of(&out);
    let prefix = "Detector Set: ";
    let line = stdout
        .lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no `Detector Set:` line in:\n{stdout}"));
    let count_str = line[prefix.len()..]
        .split_whitespace()
        .next()
        .expect("count token after `Detector Set: `");
    let printed: usize = count_str.parse().expect("detector count is a number");
    assert_eq!(
        printed,
        keyhog_core::embedded_detector_count(),
        "`--version` detector count must equal the embedded corpus size"
    );
}

#[test]
fn plain_version_omits_simd_line_while_full_includes_it() {
    // Negative twin: the hardware-probe block is gated behind `--full`.
    let plain = run(&["--version"]);
    let full = run(&["--version", "--full"]);
    assert_eq!(plain.status.code(), Some(0));
    assert_eq!(full.status.code(), Some(0));
    let plain_stdout = stdout_of(&plain);
    let full_stdout = stdout_of(&full);
    assert!(
        !plain_stdout.contains("SIMD Regex:"),
        "plain `--version` must NOT print the hardware `SIMD Regex:` line; got:\n{plain_stdout}"
    );
    assert!(
        full_stdout.contains("SIMD Regex:"),
        "`--version --full` must print the `SIMD Regex:` hardware line; got:\n{full_stdout}"
    );
}

#[test]
fn full_flag_without_version_is_a_usage_error_naming_version() {
    // Boundary: `--full` has `requires = "version"`; alone it must fail clap
    // validation with exit 2 and name the missing `--version`.
    let out = run(&["--full"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "`--full` without `--version` must exit 2"
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("required arguments were not provided") && stderr.contains("--version"),
        "usage error must name the missing `--version`; got:\n{stderr}"
    );
}

// ── Top-level help surface ───────────────────────────────────────────────

#[test]
fn help_lists_every_real_subcommand_and_usage() {
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0), "--help must exit 0");
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("Usage: keyhog"),
        "help must show the top-level usage line"
    );
    for sub in [
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
    ] {
        assert!(
            stdout.contains(sub),
            "help must name the `{sub}` subcommand; got:\n{stdout}"
        );
    }
    assert!(
        !stdout.contains("frobnicate"),
        "help must not invent nonexistent subcommands"
    );
}

#[test]
fn help_embeds_the_exit_code_contract_verbatim() {
    // Cross-check: the rendered `EXIT CODES:` block in `--help` must be the
    // exact string produced by the crate's single-source-of-truth renderer.
    let out = run(&["--help"]);
    let stdout = stdout_of(&out);
    let contract = keyhog::exit_codes::help();
    assert!(
        stdout.contains(contract),
        "help must embed the exit-code contract verbatim; expected:\n{contract}\n---got---\n{stdout}"
    );
}

// ── Adversarial argument handling ────────────────────────────────────────

#[test]
fn unknown_subcommand_exits_2_and_names_it() {
    let out = run(&["frobnicate"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "unknown subcommand must exit 2 (user error)"
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("unrecognized subcommand 'frobnicate'"),
        "error must name the unrecognized subcommand; got:\n{stderr}"
    );
}

#[test]
fn unknown_top_level_flag_exits_2() {
    let out = run(&["--nope"]);
    assert_eq!(out.status.code(), Some(2), "unknown flag must exit 2");
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("unexpected argument '--nope'"),
        "error must name the unexpected argument; got:\n{stderr}"
    );
}

#[test]
fn bare_invocation_prints_help_and_exits_0() {
    let out = run(&[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "no-args invocation prints help and exits 0"
    );
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("Usage: keyhog") && stdout.contains("Commands:"),
        "no-args help must show usage + command list; got:\n{stdout}"
    );
}

// ── doctor: self-test + exit 0 on this host ──────────────────────────────

#[test]
fn doctor_header_and_self_test_pass_line_exit_0() {
    let out = run(&["doctor"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "doctor self-test must exit 0 on a healthy build/host"
    );
    let stdout = stdout_of(&out);
    let first = stdout.lines().next().expect("doctor prints a header line");
    let expected_header = format!("keyhog doctor  v{}", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        first, expected_header,
        "doctor header must carry the exact crate version"
    );
    assert!(
        stdout.contains("scan engine") && stdout.contains("planted secret detected end-to-end"),
        "doctor must print the end-to-end scan self-test PASS line; got:\n{stdout}"
    );
}

#[test]
fn doctor_reports_embedded_detector_corpus_count() {
    let out = run(&["doctor"]);
    let stdout = stdout_of(&out);
    let expected = format!(
        "{} service detectors",
        keyhog_core::embedded_detector_count()
    );
    assert!(
        stdout.contains(expected.as_str()),
        "doctor must report the embedded corpus size `{expected}`; got:\n{stdout}"
    );
}

// ── daemon admin surface (no daemon running) ─────────────────────────────

#[test]
fn daemon_status_with_no_daemon_exits_2_and_guides_to_start() {
    let dir = tempfile::tempdir().expect("create user-owned temp dir");
    let sock = dir.path().join("keyhog.sock");
    let sock_str = sock.to_str().expect("utf-8 socket path");
    let out = run(&["daemon", "status", "--socket", sock_str]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "daemon status with no daemon is a user error (exit 2)"
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("daemon status: no daemon at")
            && stderr.contains(sock_str)
            && stderr.contains("keyhog daemon start"),
        "status error must name the socket and point at `keyhog daemon start`; got:\n{stderr}"
    );
}

#[test]
fn daemon_stop_with_no_daemon_exits_2_and_says_already_stopped() {
    let dir = tempfile::tempdir().expect("create user-owned temp dir");
    let sock = dir.path().join("keyhog.sock");
    let sock_str = sock.to_str().expect("utf-8 socket path");
    let out = run(&["daemon", "stop", "--socket", sock_str]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "daemon stop with no daemon is a user error (exit 2)"
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("daemon stop: no daemon at")
            && stderr.contains("already stopped")
            && stderr.contains(sock_str),
        "stop error must name the socket and note it may already be stopped; got:\n{stderr}"
    );
}

#[test]
fn daemon_without_action_is_usage_error_exit_2() {
    let out = run(&["daemon"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "`daemon` with no subaction must exit 2"
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("Usage: keyhog daemon"),
        "missing-subcommand error must show the daemon usage line; got:\n{stderr}"
    );
}

#[test]
fn daemon_help_names_start_stop_status_subactions() {
    let out = run(&["daemon", "--help"]);
    assert_eq!(out.status.code(), Some(0), "daemon --help must exit 0");
    let stdout = stdout_of(&out);
    for action in ["start", "stop", "status"] {
        assert!(
            stdout.contains(action),
            "daemon help must name the `{action}` subaction; got:\n{stdout}"
        );
    }
    assert!(
        stdout.contains(
            "Print uptime, scans served, active scans, detector count, and backend policy"
        ),
        "daemon help must carry the `status` description; got:\n{stdout}"
    );
}

#[test]
fn daemon_status_help_describes_its_output_exit_0() {
    let out = run(&["daemon", "status", "--help"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "daemon status --help must exit 0"
    );
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains(
            "Print uptime, scans served, active scans, detector count, and backend policy"
        ),
        "status --help must describe exactly what it prints; got:\n{stdout}"
    );
    assert!(
        stdout.contains("--socket"),
        "status --help must document the --socket override; got:\n{stdout}"
    );
}

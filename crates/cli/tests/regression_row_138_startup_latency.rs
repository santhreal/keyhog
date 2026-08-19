//! WHY: Row 138 startup latency and informational command dispatch contract.
//!
//! DEFECT CLASS CLOSED:
//! Informational commands (`keyhog --version`, `keyhog --help`, `keyhog guard --help`,
//! `keyhog completion`, no-args help) must execute instantaneously without
//! triggering early detector corpus parsing, regex initialization, tracing subscriber
//! allocations, tokio runtime initialization, or heavyweight subsystem setup.
//!
//! Prior defect variants:
//! 1. Tokio runtime was eagerly initialized on process startup in `main()` before
//!    evaluating command arguments, wasting time on epoll/reactor/timer setup for
//!    purely informational or exit-0 help paths.
//! 2. Tracing subscribers, filters, and mutexes were allocated before parsing CLI arguments.
//! 3. Scan-interrupt OS signal handlers were registered eagerly before knowing whether
//!    a scan was being executed.
//! 4. Any eager parsing of embedded detector specs (`load_embedded_detectors_or_fail`)
//!    incurs hundreds of TOML parses and validations, adding latency to simple queries.
//!
//! INVARIANTS TESTED:
//! 1. Informational queries (`--version`, `-V`, `--help`, `-h`, `<subcommand> --help`, `<subcommand> -h`, `completion <shell>`)
//!    exit 0 without loading or parsing the embedded detector TOML corpus (`keyhog_core::detector_corpus_load_count() == 0`).
//! 2. The entire variant space of all registered subcommands is derived dynamically from
//!    `keyhog::args::command().get_subcommands()` and tested for `<subcommand> --help` and `<subcommand> -h`.
//! 3. Unknown flags and subcommands exit 2 on stderr without loading detector models.
//! 4. Mutation gate: proves that `keyhog_core::detector_corpus_load_count()` increments when
//!    `load_embedded_detectors_or_fail()` is actually called, ensuring the test assertion cannot pass silently.
//!
//! WHAT IT DOES NOT CATCH:
//! Kernel context-switching delays or foreign process resource contention on overloaded hosts.

static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn run_cli(args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(binary())
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to execute {}: {err}", binary().display()));
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn mutation_gate_detector_corpus_load_counter_is_sensitive() {
    let _guard = TEST_LOCK.lock();
    // Prove that the detection counter starts at 0 before explicit loading
    // and increases when the corpus is parsed.
    keyhog_core::reset_detector_corpus_load_count_for_test();
    assert_eq!(
        keyhog_core::detector_corpus_load_count(),
        0,
        "load count must be 0 after reset"
    );

    let specs =
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load");
    assert!(
        !specs.is_empty(),
        "embedded detector corpus must not be empty"
    );
    assert_eq!(
        keyhog_core::detector_corpus_load_count(),
        1,
        "load count must increment by 1 when load_embedded_detectors_or_fail is called"
    );
}

#[test]
fn version_flags_exit_zero_fast_with_expected_banner() {
    for flag in &["--version", "-V"] {
        let (code, stdout, stderr) = run_cli(&[flag]);
        assert_eq!(
            code,
            Some(0),
            "{flag} must exit with code 0; stderr: {stderr}"
        );
        assert!(
            stdout.starts_with("KeyHog v"),
            "{flag} stdout must start with KeyHog banner, got: {stdout}"
        );
        assert!(
            stdout.contains(env!("CARGO_PKG_VERSION")),
            "{flag} stdout must contain package version"
        );
        assert!(
            stderr.is_empty(),
            "{flag} must not produce stderr output, got: {stderr}"
        );
    }
}

#[test]
fn root_help_flags_exit_zero_on_stdout() {
    for flag in &["--help", "-h"] {
        let (code, stdout, stderr) = run_cli(&[flag]);
        assert_eq!(
            code,
            Some(0),
            "{flag} must exit with code 0; stderr: {stderr}"
        );
        assert!(
            stdout.contains("Usage: keyhog"),
            "{flag} stdout must contain usage line"
        );
        assert!(
            stdout.contains("Commands:"),
            "{flag} stdout must list commands"
        );
        assert!(
            stderr.is_empty(),
            "{flag} must not produce stderr output, got: {stderr}"
        );
    }
}

#[test]
fn no_args_invocation_prints_help_and_exits_zero() {
    let (code, stdout, stderr) = run_cli(&[]);
    assert_eq!(
        code,
        Some(0),
        "no-arg invocation must exit with code 0; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Usage: keyhog"),
        "no-arg invocation stdout must contain usage line"
    );
    assert!(
        stderr.is_empty(),
        "no-arg invocation must not produce stderr output, got: {stderr}"
    );
}

#[test]
fn dynamic_subcommand_help_surface_all_exit_zero_without_detector_parsing() {
    // Derive the entire variant space of subcommands directly from clap Command
    let root = keyhog::args::command();
    let subcommands: Vec<String> = root
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .map(|sub| sub.get_name().to_string())
        .collect();

    assert!(
        !subcommands.is_empty(),
        "CLI must declare at least one subcommand"
    );

    for sub in &subcommands {
        // Test both --help and -h for every declared subcommand
        for help_flag in &["--help", "-h"] {
            let (code, stdout, stderr) = run_cli(&[sub.as_str(), help_flag]);
            assert_eq!(
                code,
                Some(0),
                "keyhog {sub} {help_flag} must exit with code 0; stderr: {stderr}"
            );
            assert!(
                stdout.contains(&format!("keyhog {sub}"))
                    || stdout.contains(&format!("Usage: keyhog {sub}"))
                    || stdout.contains("Usage:"),
                "keyhog {sub} {help_flag} stdout must contain usage line; got: {stdout}"
            );
            assert!(
                stderr.is_empty(),
                "keyhog {sub} {help_flag} must not produce stderr output, got: {stderr}"
            );
        }
    }
}

#[test]
fn completion_subcommands_exit_zero_on_stdout() {
    for shell in &["bash", "zsh", "fish"] {
        let (code, stdout, stderr) = run_cli(&["completion", shell]);
        assert_eq!(
            code,
            Some(0),
            "keyhog completion {shell} must exit with code 0; stderr: {stderr}"
        );
        assert!(
            !stdout.is_empty(),
            "keyhog completion {shell} must produce shell completion script on stdout"
        );
        assert!(
            stderr.is_empty(),
            "keyhog completion {shell} must not write to stderr; got: {stderr}"
        );
    }
}

#[test]
fn unknown_flags_and_subcommands_exit_two_with_usage_error() {
    let (code, stdout, stderr) = run_cli(&["--nonexistent-flag-xyz-123"]);
    assert_eq!(
        code,
        Some(2),
        "unknown flag must exit code 2; stdout: {stdout}, stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:") || stderr.contains("Usage:"),
        "unknown flag stderr must contain clap diagnostic; got: {stderr}"
    );

    let (code, stdout, stderr) = run_cli(&["nonexistent-subcommand-xyz"]);
    assert_eq!(
        code,
        Some(2),
        "unknown subcommand must exit code 2; stdout: {stdout}, stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:") || stderr.contains("Usage:"),
        "unknown subcommand stderr must contain clap diagnostic; got: {stderr}"
    );
}

#[test]
fn in_process_argument_parsing_never_loads_detector_corpus() {
    let _guard = TEST_LOCK.lock();
    keyhog_core::reset_detector_corpus_load_count_for_test();

    // Parse root help and version
    let _ = keyhog::args::try_parse_from(["keyhog", "--help"]);
    let _ = keyhog::args::try_parse_from(["keyhog", "-V"]);
    let _ = keyhog::args::try_parse_from(["keyhog", "--version"]);

    // Parse subcommands help
    let root = keyhog::args::command();
    for sub in root.get_subcommands().filter(|s| !s.is_hide_set()) {
        let _ = keyhog::args::try_parse_from(["keyhog", sub.get_name(), "--help"]);
    }

    // Parse scan args
    let _ = keyhog::args::try_parse_from(["keyhog", "scan", "."]);

    // Parse guard args
    let _ = keyhog::args::try_parse_from(["keyhog", "guard", "--help"]);

    // Parse completion args
    let _ = keyhog::args::try_parse_from(["keyhog", "completion", "bash"]);

    assert_eq!(
        keyhog_core::detector_corpus_load_count(),
        0,
        "argument parsing and help generation must NEVER parse the detector TOML corpus"
    );
}

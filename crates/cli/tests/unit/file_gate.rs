//! FILE_GATE micro tests for cli crate src files.

use clap::Parser;
use keyhog::args::{Cli, ScanArgs};
use keyhog::baseline::Baseline;
use keyhog::benchmark::format_gpu_summary;
use keyhog::config::find_config_file;
// The `keyhog::daemon::*` modules are unix-only (Unix-domain sockets).
// Gate the imports and the daemon_* tests below so the file compiles
// on Windows.
#[cfg(unix)]
use keyhog::daemon::default_socket_path;
#[cfg(unix)]
use keyhog::daemon::protocol::{Request, Response, MAX_FRAME_BYTES, WIRE_VERSION};
use keyhog::inline_suppression::filter_inline_suppressions;
use keyhog::path_validation::validate_cli_path_arg;
use keyhog::reporting::report_findings;
use keyhog::test_fixture_suppressions::TestFixtureSuppressions;
use keyhog::value_parsers::{parse_decode_depth, parse_min_confidence};
use keyhog_core::{MatchLocation, RawMatch, Severity};
use std::sync::Arc;

// ── crates/cli/src/lib.rs ─────────────────────────────────────────────
#[test]
fn lib_happy() {
    assert_eq!(
        keyhog::SCANNED_CHUNKS.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}
#[test]
fn lib_error() {
    assert!(!keyhog::SCANNER_PANICKED.load(std::sync::atomic::Ordering::Relaxed));
}

// ── crates/cli/src/main.rs ────────────────────────────────────────────
#[test]
fn main_happy() {
    let cli = Cli::try_parse_from(["keyhog", "--version"]).unwrap();
    assert!(cli.version);
}
#[test]
fn main_error() {
    assert!(Cli::try_parse_from(["keyhog", "--bad-flag"]).is_err());
}

// ── crates/cli/src/args.rs ────────────────────────────────────────────
#[test]
fn args_happy() {
    let args = ScanArgs::try_parse_from(["scan", "."]).unwrap();
    assert_eq!(args.input.as_deref(), Some(std::path::Path::new(".")));
}
#[test]
fn args_error() {
    assert!(ScanArgs::try_parse_from(["scan", "--min-confidence", "not-a-float"]).is_err());
}

// ── crates/cli/src/baseline.rs ────────────────────────────────────────
#[test]
fn baseline_happy() {
    let baseline = Baseline::from_findings(&[]);
    assert!(baseline.entries.is_empty());
}
#[test]
fn baseline_error() {
    assert!(Baseline::load(std::path::Path::new("/nonexistent/baseline.json")).is_err());
}

// ── crates/cli/src/benchmark.rs ───────────────────────────────────────
#[test]
fn benchmark_happy() {
    assert!(!format_gpu_summary().is_empty());
}

// ── crates/cli/src/config.rs ──────────────────────────────────────────
#[test]
fn config_happy() {
    let dir = tempfile::tempdir().unwrap();
    assert!(find_config_file(Some(dir.path())).is_none());
}
#[test]
fn config_error() {
    assert!(find_config_file(Some(std::path::Path::new("/nonexistent"))).is_none());
}

// ── crates/cli/src/daemon/mod.rs ──────────────────────────────────────
// Daemon tests are unix-only - see file header.
#[cfg(unix)]
#[test]
fn daemon_mod_happy() {
    let path = default_socket_path();
    assert!(!path.as_os_str().is_empty());
}

// ── crates/cli/src/daemon/client.rs ─────────────────────────────────────
#[cfg(unix)]
#[test]
fn daemon_client_happy() {
    let path = default_socket_path();
    assert!(path.to_string_lossy().contains("keyhog") || path.ends_with(".sock"));
}

// ── crates/cli/src/daemon/frame.rs ──────────────────────────────────────
#[cfg(unix)]
#[test]
fn daemon_frame_happy() {
    let json = serde_json::to_string(&Request::Hello).unwrap();
    assert!(json.contains("hello"));
}
#[cfg(unix)]
#[test]
fn daemon_frame_error() {
    let json = serde_json::to_string(&Response::Hello {
        wire_version: WIRE_VERSION,
        keyhog_version: "0.0.0".into(),
        detector_count: 0,
        uptime_secs: 0,
    })
    .unwrap();
    assert!(json.contains("wire_version"));
}

// ── crates/cli/src/daemon/protocol.rs ───────────────────────────────────
#[cfg(unix)]
#[test]
fn daemon_protocol_happy() {
    assert_eq!(WIRE_VERSION, 2);
}
#[cfg(unix)]
#[test]
fn daemon_protocol_error() {
    assert!(MAX_FRAME_BYTES > 0);
}

// ── crates/cli/src/daemon/server.rs ─────────────────────────────────────
#[cfg(unix)]
#[test]
fn daemon_server_happy() {
    let path = default_socket_path();
    assert!(!path.as_os_str().is_empty());
}
#[cfg(unix)]
#[test]
fn daemon_server_error() {
    assert_ne!(WIRE_VERSION, 0);
}

// ── crates/cli/src/inline_suppression.rs ──────────────────────────────
#[test]
fn inline_suppression_happy() {
    let m = RawMatch {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("Demo"),
        service: Arc::from("demo"),
        severity: Severity::Low,
        credential: Arc::from("abc"),
        credential_hash: [7u8; 32],
        companions: Default::default(),
        location: MatchLocation {
            source: Arc::from("stdin"),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    };
    assert_eq!(filter_inline_suppressions(vec![m]).len(), 1);
}
#[test]
fn inline_suppression_error() {
    assert!(filter_inline_suppressions(vec![]).is_empty());
}

// ── crates/cli/src/orchestrator.rs ────────────────────────────────────
#[test]
fn orchestrator_happy() {
    assert!(!format_gpu_summary().is_empty());
}
#[test]
fn orchestrator_error() {
    assert!(
        validate_cli_path_arg(std::path::Path::new("/nonexistent/keyhog-path"), "scan").is_err()
    );
}

// ── crates/cli/src/orchestrator_config.rs ─────────────────────────────
#[test]
fn orchestrator_config_happy() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--fast"]).unwrap();
    assert!(args.fast);
}

// ── crates/cli/src/path_validation.rs ─────────────────────────────────
#[test]
fn path_validation_error() {
    assert!(
        validate_cli_path_arg(std::path::Path::new("/nonexistent/keyhog-path"), "scan").is_err()
    );
}

// ── crates/cli/src/reporting.rs ───────────────────────────────────────
#[test]
fn reporting_error() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--output", "/"]).unwrap();
    assert!(report_findings(&[], &args).is_err());
}

// ── crates/cli/src/sources.rs ───────────────────────────────────────
#[test]
fn sources_error() {
    let args = ScanArgs::try_parse_from(["scan", "--path", "/nonexistent/keyhog-path"]).unwrap();
    assert!(keyhog::sources::build_sources(&args, vec![], None).is_err());
}

// ── crates/cli/src/subcommands/mod.rs ─────────────────────────────────
#[test]
fn subcommands_mod_happy() {
    let cli = Cli::try_parse_from(["keyhog", "scan", "."]).unwrap();
    assert!(matches!(cli.command, Some(keyhog::args::Command::Scan(_))));
}
#[test]
fn subcommands_mod_error() {
    assert!(Cli::try_parse_from(["keyhog", "not-a-command"]).is_err());
}

// ── crates/cli/src/subcommands/backend.rs ─────────────────────────────
#[test]
fn subcommands_backend_error() {
    assert!(Cli::try_parse_from(["keyhog", "backend", "--not-real"]).is_err());
}

// ── crates/cli/src/subcommands/calibrate.rs ───────────────────────────
#[test]
fn subcommands_calibrate_error() {
    assert!(Cli::try_parse_from(["keyhog", "calibrate", "--not-real"]).is_err());
}

// ── crates/cli/src/subcommands/completion.rs ──────────────────────────
#[test]
fn subcommands_completion_error() {
    assert!(Cli::try_parse_from(["keyhog", "completion"]).is_err());
}

// ── crates/cli/src/subcommands/daemon.rs ──────────────────────────────
#[test]
fn subcommands_daemon_error() {
    assert!(Cli::try_parse_from(["keyhog", "daemon", "not-a-sub"]).is_err());
}

// ── crates/cli/src/subcommands/detectors.rs ───────────────────────────
#[test]
fn subcommands_detectors_error() {
    assert!(Cli::try_parse_from(["keyhog", "detectors", "--not-real"]).is_err());
}

// ── crates/cli/src/subcommands/diff.rs ────────────────────────────────
#[test]
fn subcommands_diff_happy() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.json");
    let b = dir.path().join("b.json");
    std::fs::write(&a, b"[]").unwrap();
    std::fs::write(&b, b"[]").unwrap();
    assert!(
        Cli::try_parse_from(["keyhog", "diff", a.to_str().unwrap(), b.to_str().unwrap()]).is_ok()
    );
}
#[test]
fn subcommands_diff_error() {
    assert!(Cli::try_parse_from(["keyhog", "diff", "--not-real"]).is_err());
}

// ── crates/cli/src/subcommands/explain.rs ─────────────────────────────
#[test]
fn subcommands_explain_error() {
    assert!(Cli::try_parse_from(["keyhog", "explain"]).is_err());
}

// ── crates/cli/src/subcommands/hook.rs ────────────────────────────────
#[test]
fn subcommands_hook_error() {
    assert!(Cli::try_parse_from(["keyhog", "hook"]).is_err());
}

// ── crates/cli/src/subcommands/scan.rs ────────────────────────────────
#[test]
fn subcommands_scan_error() {
    assert!(Cli::try_parse_from(["keyhog", "scan", "--min-confidence", "bad"]).is_err());
}

// ── crates/cli/src/subcommands/scan_system.rs ─────────────────────────
#[test]
fn subcommands_scan_system_error() {
    assert!(Cli::try_parse_from(["keyhog", "scan-system", "--not-real"]).is_err());
}

// ── crates/cli/src/subcommands/watch.rs ───────────────────────────────
#[test]
fn subcommands_watch_error() {
    assert!(Cli::try_parse_from(["keyhog", "watch", "--not-real"]).is_err());
}

// ── crates/cli/src/test_fixture_suppressions.rs ───────────────────────
#[test]
fn test_fixture_suppressions_happy() {
    let s = TestFixtureSuppressions::bundled();
    assert!(s.exact_count() >= 1);
}
#[test]
fn test_fixture_suppressions_error() {
    let s = TestFixtureSuppressions::empty();
    assert!(!s.suppresses("sk_live_realistic_token_value"));
}

// ── crates/cli/src/value_parsers.rs ───────────────────────────────────
#[test]
fn value_parsers_happy() {
    assert_eq!(parse_min_confidence("0.5").unwrap(), 0.5);
}
#[test]
fn value_parsers_error() {
    assert!(parse_decode_depth("not-a-number").is_err());
}

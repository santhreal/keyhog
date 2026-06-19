//! FILE_GATE micro tests for cli crate src files.

use clap::Parser;
use keyhog::args::{Cli, ScanArgs};
use keyhog::testing::{CliTestApi as _, API};
// The `keyhog::daemon::*` modules are unix-only (Unix-domain sockets).
// Gate the imports and the daemon_* tests below so the file compiles
// on Windows.
#[cfg(unix)]
use keyhog::daemon::default_socket_path;
#[cfg(unix)]
use keyhog::daemon::protocol::{Request, Response, MAX_FRAME_BYTES, WIRE_VERSION};
use keyhog_core::{Chunk, ChunkMetadata, MatchLocation, RawMatch, SensitiveString, Severity};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── crates/cli/src/lib.rs ─────────────────────────────────────────────
#[test]
fn lib_happy() {
    assert_eq!(API.scanned_chunks(), 0);
}
#[test]
fn lib_error() {
    assert!(!API.scanner_panicked());
}

#[test]
fn lib_scan_failure_counters_have_typed_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib = std::fs::read_to_string(root.join("src/lib.rs")).expect("read cli lib");
    let dispatch =
        std::fs::read_to_string(root.join("src/orchestrator/dispatch.rs")).expect("read dispatch");
    let fused = std::fs::read_to_string(root.join("src/orchestrator/dispatch/fused.rs"))
        .expect("read fused dispatch");

    assert!(
        lib.contains("enum ScanFailureEvent") && lib.contains("struct RecordedScanFailureEvent"),
        "CLI scan failures need a typed event owner and must-use receipt"
    );
    for (name, source) in [
        ("dispatch", dispatch.as_str()),
        ("fused dispatch", fused.as_str()),
    ] {
        assert!(
            source.contains("record_source_error") || source.contains("record_scanner_panic"),
            "{name} must record failure state through typed recorders"
        );
        assert!(
            !source.contains("SOURCE_ERRORS.fetch_add")
                && !source.contains("FAILED_SOURCES.fetch_add")
                && !source.contains("SCANNER_PANICKED.store"),
            "{name} must not mutate scan-failure counters directly"
        );
    }
    assert!(
        fused.contains("fused source drain thread panicked")
            && fused.contains("record_scanner_panic()")
            && !fused.contains("let _ = drain.join()"),
        "fused dispatch must fail loud when the source drain thread panics, not ignore the join result"
    );
}

#[test]
fn scan_runtime_reset_clears_process_global_scan_state() {
    API.seed_scan_runtime_state_for_test();
    let seeded = API.scan_runtime_snapshot();
    assert!(
        seeded.scanned_chunks > 0
            && seeded.total_chunks > 0
            && seeded.findings_count > 0
            && seeded.gpu_scanned_chunks > 0
            && seeded.source_errors > 0
            && seeded.failed_sources > 0
            && seeded.scanner_panicked
            && seeded.dogfood_enabled
            && seeded.example_suppressions > 0,
        "test setup must seed every runtime counter that can leak across scans: {seeded:?}"
    );

    API.reset_scan_runtime_state_for_test();

    assert_eq!(
        API.scan_runtime_snapshot(),
        keyhog::testing::ScanRuntimeSnapshot::default(),
        "per-scan runtime reset must clear CLI totals, failure flags, scanner dogfood state, \
         suppression counts, and scanner coverage-gap counters"
    );
}

#[test]
fn scan_runtime_reset_runs_before_dogfood_enablement() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let run = std::fs::read_to_string(root.join("src/orchestrator/run.rs")).expect("read run");
    let lib = std::fs::read_to_string(root.join("src/lib.rs")).expect("read cli lib");

    let reset_pos = run
        .find("reset_scan_runtime_state();")
        .expect("run boundary must reset process-global scan state");
    let dogfood_pos = run
        .find("enable_dogfood();")
        .expect("dogfood enablement still happens in run");
    assert!(
        reset_pos < dogfood_pos,
        "reset must happen before --dogfood enablement so stale dogfood state is cleared \
         without disabling the current scan's requested trace"
    );
    for token in [
        "SCANNED_CHUNKS.store(0",
        "TOTAL_CHUNKS.store(0",
        "FINDINGS_COUNT.store(0",
        "GPU_SCANNED_CHUNKS.store(0",
        "SOURCE_ERRORS.store(0",
        "FAILED_SOURCES.store(0",
        "SCANNER_PANICKED.store(false",
        "keyhog_scanner::telemetry::reset_for_scan()",
    ] {
        assert!(
            lib.contains(token),
            "reset_scan_runtime_state must clear {token}"
        );
    }
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
    let baseline = API.baseline_from_findings(&[]);
    assert!(baseline.entries.is_empty());
}
#[test]
fn baseline_error() {
    assert!(API
        .baseline_load(std::path::Path::new("/nonexistent/baseline.json"))
        .is_err());
}

// ── crates/cli/src/benchmark.rs ───────────────────────────────────────
#[test]
fn benchmark_happy() {
    assert!(!API.format_gpu_summary().is_empty());
}

// ── crates/cli/src/config.rs ──────────────────────────────────────────
#[test]
fn config_happy() {
    let dir = tempfile::tempdir().unwrap();
    assert!(API.find_config_file(Some(dir.path())).is_none());
}
#[test]
fn config_error() {
    assert!(API
        .find_config_file(Some(std::path::Path::new("/nonexistent")))
        .is_none());
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
        credential: keyhog_core::SensitiveString::from("abc"),
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
    assert_eq!(API.filter_inline_suppressions(vec![m]).len(), 1);
}
#[test]
fn inline_suppression_error() {
    assert!(API.filter_inline_suppressions(vec![]).is_empty());
}

// ── crates/cli/src/orchestrator.rs ────────────────────────────────────
#[test]
fn orchestrator_happy() {
    assert!(!API.format_gpu_summary().is_empty());
}
#[test]
fn orchestrator_error() {
    assert!(API
        .validate_cli_path_arg(std::path::Path::new("/nonexistent/keyhog-path"), "scan")
        .is_err());
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
    assert!(API
        .validate_cli_path_arg(std::path::Path::new("/nonexistent/keyhog-path"), "scan")
        .is_err());
}

// ── crates/cli/src/reporting.rs ───────────────────────────────────────
#[test]
fn reporting_error() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--output", "/"]).unwrap();
    assert!(API.report_findings(&[], &args).is_err());
}

#[test]
fn reporting_sarif_includes_scanner_decode_truncation_gap() {
    API.reset_scan_runtime_state_for_test();
    let chunk = Chunk {
        data: SensitiveString::from("plain inert text"),
        metadata: ChunkMetadata {
            path: Some("encoded/audit.txt".to_string()),
            ..Default::default()
        },
    };
    let past_deadline = Instant::now() - Duration::from_millis(1);
    let _decoded =
        keyhog_scanner::testing::decode_chunk(&chunk, 1, false, Some(past_deadline), None);
    assert!(
        API.scan_runtime_snapshot().decode_truncations > 0,
        "test setup must create a real scanner decode-through truncation"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("report.sarif");
    let out_s = out.to_string_lossy().into_owned();
    let args = ScanArgs::try_parse_from(["scan", ".", "--format", "sarif", "--output", &out_s])
        .expect("parse sarif output args");
    API.report_findings(&[], &args)
        .expect("write SARIF report with scanner coverage gap");

    let sarif: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).expect("read SARIF")).expect("SARIF JSON");
    let notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .expect("scanner decode truncation must create SARIF notifications");
    assert!(
        notifications.iter().any(|notification| {
            notification["properties"]["reason"].as_str()
                == Some("scanner decode-through truncated by budget/cap (raw bytes scanned; deeper encoded layers not expanded)")
                && notification["properties"]["count"].as_u64().is_some_and(|count| count >= 1)
        }),
        "SARIF notifications must include the scanner decode truncation gap; sarif={sarif}"
    );
    API.reset_scan_runtime_state_for_test();
}

// ── crates/cli/src/sources.rs ───────────────────────────────────────
#[test]
fn sources_error() {
    let args = ScanArgs::try_parse_from(["scan", "--path", "/nonexistent/keyhog-path"]).unwrap();
    assert!(API.build_sources(&args, vec![], None).is_err());
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
    let s = API.bundled_test_fixture_suppressions();
    assert!(API.test_fixture_exact_count(&s) >= 1);
}
#[test]
fn test_fixture_suppressions_error() {
    let s = API.empty_test_fixture_suppressions();
    assert!(!API.test_fixture_suppresses(&s, "sk_live_realistic_token_value"));
}

// ── crates/cli/src/value_parsers.rs ───────────────────────────────────
#[test]
fn value_parsers_happy() {
    assert_eq!(API.parse_min_confidence("0.5").unwrap(), 0.5);
}
#[test]
fn value_parsers_error() {
    assert!(API.parse_decode_depth("not-a-number").is_err());
}

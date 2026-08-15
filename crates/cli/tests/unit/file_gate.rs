//! FILE_GATE micro tests for cli crate src files.

use clap::Parser;
use keyhog::args::{Cli, ScanArgs};
use keyhog::exit_codes::{EXIT_FINDINGS, EXIT_SOURCE_FAILED, EXIT_SYSTEM_ERROR};
use keyhog::testing::{CliTestApi as _, API};
// The public daemon facade is Unix-only because it resolves a Unix socket path.
#[cfg(unix)]
use keyhog::daemon::default_socket_path;
use keyhog_core::{Chunk, ChunkMetadata, MatchLocation, RawMatch, SensitiveString, Severity};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── crates/cli/src/lib.rs ─────────────────────────────────────────────
#[test]
fn lib_happy() {
    let _guard = API.scan_runtime_guard_for_test();
    API.reset_scan_runtime_state_for_test(&_guard);
    assert_eq!(API.scanned_chunks(&_guard), 0);
}
#[test]
fn lib_error() {
    let _guard = API.scan_runtime_guard_for_test();
    API.reset_scan_runtime_state_for_test(&_guard);
    assert!(!API.scanner_panicked(&_guard));
}

#[test]
fn scan_exit_precedence_keeps_system_failure_above_source_coverage_gap() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(
        API.resolve_scan_exit_for_test(true, true, true),
        EXIT_FINDINGS,
        "findings outrank cache and source coverage failures"
    );
    assert_eq!(
        API.resolve_scan_exit_for_test(false, true, true),
        EXIT_SYSTEM_ERROR,
        "cache failure outranks a source coverage failure"
    );
    assert_eq!(
        API.resolve_scan_exit_for_test(false, false, true),
        EXIT_SOURCE_FAILED,
        "source coverage failure remains fail-closed"
    );
    let run = std::fs::read_to_string(root.join("src/orchestrator/run.rs")).expect("read run");
    assert!(
        run.contains("crate::reporting::CoverageCounts::current().fail_class_total()"),
        "source, scanner, and orchestrator coverage gaps must reach the canonical FAIL-class total before a clean-looking scan can exit successfully"
    );
    let reporting = std::fs::read_to_string(root.join("src/orchestrator/reporting.rs"))
        .expect("read terminal reporting");
    let report = std::fs::read_to_string(root.join("src/reporting.rs")).expect("read report");
    // Both surfaces now render the ONE canonical coverage-gap set: the terminal
    // summary iterates `CoverageGapKind::ALL`, and each category's terminal
    // (human) and structured (SARIF) wording lives with the kind in reporting.rs.
    // Assert the terminal summary renders the canonical set, and that the generic
    // source-error category carries BOTH its terminal and structured wording
    // there, so a partial source can never be surfaced on one summary and
    // silently dropped from the other.
    assert!(
        reporting.contains("CoverageGapKind::ALL") && reporting.contains("human_reason"),
        "terminal coverage summary must render the canonical CoverageGapKind set"
    );
    assert!(
        report.contains("source error row(s) emitted")
            && report.contains("requested input was NOT fully scanned"),
        "canonical set must carry the terminal (human) wording for generic source errors"
    );
    assert!(
        report.contains("source emitted error rows")
            && report.contains("requested input was not fully scanned"),
        "canonical set must carry the structured (SARIF) wording for generic source errors"
    );
}

#[test]
fn scan_runtime_reset_clears_process_global_scan_state() {
    let _guard = API.scan_runtime_guard_for_test();
    API.seed_scan_runtime_state_for_test(&_guard);
    let seeded = API.scan_runtime_snapshot(&_guard);
    assert!(
        seeded.scanned_chunks > 0
            && seeded.total_chunks > 0
            && seeded.findings_count > 0
            && seeded.gpu_scanned_chunks > 0
            && seeded.source_errors > 0
            && seeded.failed_sources > 0
            && seeded.incremental_cache_errors > 0
            && seeded.scanner_panicked
            && seeded.dogfood_enabled
            && seeded.example_suppressions > 0,
        "test setup must seed every runtime counter that can leak across scans: {seeded:?}"
    );

    API.reset_scan_runtime_state_for_test(&_guard);

    assert_eq!(
        API.scan_runtime_snapshot(&_guard),
        keyhog::testing::ScanRuntimeSnapshot::default(),
        "per-scan runtime reset must clear CLI totals, failure flags, scanner dogfood state, \
         suppression counts, and scanner coverage-gap counters"
    );
}

#[test]
fn scan_runtime_guard_recovers_from_poisoned_test_lock() {
    let joined = std::thread::spawn(|| {
        let _guard = API.scan_runtime_guard_for_test();
        panic!("poison CLI scan-runtime test lock");
    })
    .join();
    assert!(
        joined.is_err(),
        "poisoning setup should panic inside thread"
    );

    let guard = API.scan_runtime_guard_for_test();
    API.reset_scan_runtime_state_for_test(&guard);
    assert_eq!(API.scan_runtime_snapshot(&guard), Default::default());
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
        "INCREMENTAL_CACHE_ERRORS.store(0",
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
    assert!(cli.build_version);
}
#[test]
fn main_error() {
    assert!(Cli::try_parse_from(["keyhog", "--bad-flag"]).is_err());
}

// ── crates/cli/src/args.rs ────────────────────────────────────────────
#[test]
fn args_happy() {
    let args = ScanArgs::try_parse_from(["scan", "."]).unwrap();
    assert_eq!(args.input, vec![std::path::PathBuf::from(".")]);
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

// ── crates/cli/src/daemon/server.rs ─────────────────────────────────────
#[cfg(unix)]
#[test]
fn daemon_server_happy() {
    let path = default_socket_path();
    assert!(!path.as_os_str().is_empty());
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
        credential_hash: [7u8; 32].into(),
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
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
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
    let _guard = API.scan_runtime_guard_for_test();
    let args = ScanArgs::try_parse_from(["scan", ".", "--output", "/"]).unwrap();
    assert!(API.report_findings(&[], &args, &_guard).is_err());
}

#[test]
fn reporting_sarif_includes_scanner_decode_truncation_gap() {
    let _guard = API.scan_runtime_guard_for_test();
    API.reset_scan_runtime_state_for_test(&_guard);
    let chunk = Chunk {
        data: SensitiveString::from("plain inert text"),
        metadata: ChunkMetadata {
            path: Some("encoded/audit.txt".into()),
            ..Default::default()
        },
    };
    let past_deadline = Instant::now() - Duration::from_millis(1);
    let _decoded =
        keyhog_scanner::testing::decode_chunk(&chunk, 1, false, Some(past_deadline), None);
    assert!(
        API.scan_runtime_snapshot(&_guard).decode_truncations > 0,
        "test setup must create a real scanner decode-through truncation"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("report.sarif");
    let out_s = out.to_string_lossy().into_owned();
    let args = ScanArgs::try_parse_from(["scan", ".", "--format", "sarif", "--output", &out_s])
        .expect("parse sarif output args");
    API.report_findings(&[], &args, &_guard)
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
    API.reset_scan_runtime_state_for_test(&_guard);
}

// ── crates/cli/src/sources.rs ───────────────────────────────────────
#[test]
fn sources_error() {
    let args = ScanArgs::try_parse_from(["scan", "--path", "/nonexistent/keyhog-path"]).unwrap();
    assert!(API.build_sources(&args, vec![], None).is_err());
}

#[test]
fn sources_wires_no_default_excludes_into_git_sources() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources = std::fs::read_to_string(root.join("src/sources.rs")).expect("read sources.rs");

    for constructor in [
        "keyhog_sources::GitSource::new(path.clone())",
        "keyhog_sources::GitDiffSource::new(repo_path, base_ref.clone())",
        "keyhog_sources::GitHistorySource::new(path.clone())",
    ] {
        let start = sources.find(constructor).unwrap_or_else(|| {
            panic!("sources.rs must construct {constructor} through the resolved config path")
        });
        let tail = &sources[start..];
        let end = tail
            .find("));")
            .expect("git source constructor chain must close");
        let chain = &tail[..end];
        assert!(
            chain.contains(".with_default_excludes(!resolved.no_default_excludes)"),
            "{constructor} must receive the resolved no-default-excludes flag"
        );
    }

    assert!(
        sources.contains("create_source_with_http_config_limits_and_policy"),
        "CLI source construction must use the policy-aware source factory"
    );
    // Anchor on the factory CALL, not on the first mention of the source name
    // anywhere in the file: the name also appears in effective-config field
    // keys, and matching those made this gate report a missing flag on a call
    // that passes it correctly.
    let mut checked = std::collections::BTreeSet::new();
    for call in sources
        .split("create_source_with_http_config_limits_and_policy(")
        .skip(1)
    {
        let call_end = call
            .find(")?")
            .expect("source factory call must close with `)?`");
        let call = &call[..call_end];
        let name = call
            .split(['"'])
            .nth(1)
            .expect("source factory call names its source")
            .to_owned();
        assert!(
            call.contains("!resolved.no_default_excludes"),
            "{name:?} source factory call must receive the resolved no-default-excludes flag"
        );
        checked.insert(name);
    }
    for required in [
        "github-org",
        "gitlab-group",
        "bitbucket-workspace",
        "docker",
    ] {
        assert!(
            checked.contains(required),
            "sources.rs must construct {required:?} through the policy-aware factory; \
             checked {checked:?}"
        );
    }
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

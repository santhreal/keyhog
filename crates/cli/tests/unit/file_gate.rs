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
                && !source.contains("INCREMENTAL_CACHE_ERRORS.fetch_add")
                && !source.contains("SCANNER_PANICKED.store"),
            "{name} must not mutate scan-failure counters directly"
        );
    }
    assert!(
        dispatch.contains("record_incremental_cache_persist_failed()")
            && dispatch.contains("could not be persisted"),
        "incremental cache persistence failures must go through the typed failure owner and stderr"
    );
    assert!(
        dispatch.contains("fn record_oversized_coalesced_chunk_skip(")
            && fused.contains("super::record_oversized_coalesced_chunk_skip(&c)")
            && fused.contains("COALESCED_CHUNK_SCAN_CEILING_BYTES"),
        "coalesced and fused oversized chunk drops must share one loud source-error recorder"
    );
    assert!(
        fused.contains("fused source drain thread panicked")
            && fused.contains("record_scanner_panic()")
            && !fused.contains("let _ = drain.join()"),
        "fused dispatch must fail loud when the source drain thread panics, not ignore the join result"
    );
    assert!(
        dispatch.contains("fn filesystem_source_skipped_unchanged")
            && dispatch.contains("skipped_unchanged_count")
            && dispatch.contains(
                "self.skipped_unchanged += filesystem_source_skipped_unchanged(source.as_ref())"
            )
            && fused.contains("super::filesystem_source_skipped_unchanged(source.as_ref())")
            && fused.contains("drain_skipped_unchanged.fetch_add(source_skipped"),
        "coalesced and fused dispatch must include file-level Merkle skips from FilesystemSource, not only chunk-level skips"
    );
}

#[test]
fn scan_exit_precedence_keeps_system_failure_above_source_coverage_gap() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let run = std::fs::read_to_string(root.join("src/orchestrator/run.rs")).expect("read run");
    let findings_pos = run
        .find("} else if has_new_entries {")
        .expect("findings exit branch");
    let incremental_pos = run
        .find("} else if incremental_cache_failed {")
        .expect("incremental cache exit branch");
    let source_gap_pos = run
        .find("} else if source_coverage_incomplete {")
        .expect("source coverage exit branch");

    assert!(
        findings_pos < incremental_pos && incremental_pos < source_gap_pos,
        "exit precedence must be live -> panic -> findings -> system/cache failure -> \
         source coverage failure. A source coverage warning must not mask a system \
         cache failure when there are no findings."
    );
    assert!(
        run.contains("let source_errors = crate::SOURCE_ERRORS.load")
            && run.contains("source_errors + source_gaps + binary_gaps + scanner_coverage_gaps > 0"),
        "source errors emitted by partial sources or orchestrator drops must make clean-looking scans exit as incomplete coverage"
    );
    let reporting = std::fs::read_to_string(root.join("src/orchestrator/reporting.rs"))
        .expect("read terminal reporting");
    let report = std::fs::read_to_string(root.join("src/reporting.rs")).expect("read report");
    assert!(
        reporting.contains("let source_errors = crate::SOURCE_ERRORS.load")
            && reporting.contains("source error row(s) emitted")
            && reporting.contains("requested input was NOT fully scanned"),
        "terminal coverage summary must name generic source errors, not only source skip counters"
    );
    assert!(
        report.contains("source emitted error rows")
            && report.contains("requested input was not fully scanned"),
        "structured coverage summaries must include generic source errors"
    );
}

#[test]
fn git_object_coverage_gaps_are_reported_separately() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let run = std::fs::read_to_string(root.join("src/orchestrator/run.rs")).expect("read run");
    let reporting = std::fs::read_to_string(root.join("src/orchestrator/reporting.rs"))
        .expect("read reporting");
    let report = std::fs::read_to_string(root.join("src/reporting.rs")).expect("read report");

    assert!(
        run.contains("counts.git_object_unreadable"),
        "git object drops must make clean-looking scans exit as incomplete coverage through the central skip snapshot"
    );
    assert!(
        reporting.contains("Git object(s) NOT scanned")
            && reporting.contains("c.git_object_unreadable"),
        "terminal summary must not lump unreadable Git objects under unreadable file wording and must read the central skip snapshot"
    );
    assert!(
        report.contains("Git object unreadable or wrong object kind")
            && report.contains("c.git_object_unreadable"),
        "structured report coverage summaries must surface the Git object gap category from the central skip snapshot"
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
fn scan_runtime_test_facade_guards_in_process_global_state() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let testing = std::fs::read_to_string(root.join("src/testing.rs")).expect("read test facade");

    assert!(
        testing.contains("#[must_use = \"hold ScanRuntimeGuard"),
        "ScanRuntimeGuard must be must-use so ignored guard acquisition is a warning"
    );
    for required in [
        "fn report_findings(\n        &self,\n        findings: &[VerifiedFinding],\n        args: &ScanArgs,\n        _guard: &ScanRuntimeGuard,",
        "fn scan_orchestrator_scan_sources_for_test(\n        &self,\n        orchestrator: &ScanOrchestrator,\n        sources: Vec<Box<dyn Source>>,\n        show_progress: bool,\n        merkle: Option<Arc<keyhog_core::MerkleIndex>>,\n        _guard: &ScanRuntimeGuard,",
        "fn seed_scan_runtime_state_for_test(&self, _guard: &ScanRuntimeGuard)",
        "fn reset_scan_runtime_state_for_test(&self, _guard: &ScanRuntimeGuard)",
        "fn scan_runtime_snapshot(&self, _guard: &ScanRuntimeGuard)",
    ] {
        assert!(
            testing.contains(required),
            "CLI test facade must require ScanRuntimeGuard for process-global scan state seam: {required}"
        );
    }

    let orchestrator_dir = root.join("tests/unit/orchestrator");
    for entry in std::fs::read_dir(&orchestrator_dir).expect("read orchestrator tests") {
        let entry = entry.expect("orchestrator test entry");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs")
            || path.file_name().and_then(|name| name.to_str()) == Some("support.rs")
        {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read orchestrator test");
        assert!(
            !source.contains("scan_orchestrator_scan_sources_for_test("),
            "{} must use support::scan_sources_for_test so the scan-runtime guard is held",
            path.display()
        );
    }
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

#[test]
fn ak_p4_cli_hot_paths_stay_linear() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let orchestrator =
        std::fs::read_to_string(root.join("src/orchestrator/mod.rs")).expect("read orchestrator");
    let scan =
        std::fs::read_to_string(root.join("src/subcommands/scan.rs")).expect("read scan command");
    let sources = std::fs::read_to_string(root.join("src/sources.rs")).expect("read sources");

    assert!(
        orchestrator.contains("detectors.retain(|d| !disabled_detectors.contains(d.id.as_str()))"),
        "disabled detector filtering must use the resolved HashSet, not a linear search per detector"
    );
    assert!(
        !orchestrator.contains("disabled_detectors.iter().any(|id| id == &d.id)"),
        "disabled detector filtering must not regress to O(detectors * disabled ids)"
    );
    assert!(
        scan.contains("let filesystem_source = std::sync::Arc::<str>::from(\"filesystem\");")
            && scan.contains("m.location.source = filesystem_source.clone();"),
        "daemon scan-path suppression normalization must hoist the filesystem Arc outside the finding loop"
    );
    assert!(
        !scan.contains("m.location.source = std::sync::Arc::from(\"filesystem\");"),
        "daemon scan-path suppression normalization must not allocate a fresh Arc per finding"
    );
    assert!(
        sources.contains("let normalized_excludes: Vec<String> = excludes")
            && sources.contains("staged_relative_path_matches_exclude(&rel, exclude)")
            && sources.contains(".strip_suffix(exclude)"),
        "staged-file exclude filtering must normalize excludes once and match suffixes without per-file format allocation"
    );
    assert!(
        !sources.contains("rel.ends_with(&format!(\"/{exclude}\"))"),
        "staged-file exclude filtering must not allocate a formatted suffix per exclude check"
    );
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
            path: Some("encoded/audit.txt".to_string()),
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

// ── crates/cli/src/subcommands/repair.rs ──────────────────────────────
#[test]
fn subcommands_repair_self_test_errors_are_visible() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let repair = std::fs::read_to_string(root.join("src/subcommands/repair.rs"))
        .expect("read repair subcommand");
    assert!(
        !repair.contains("scan_engine_self_test().unwrap_or(false)"),
        "repair must not collapse self-test errors into a boolean"
    );
    assert!(
        repair.contains("Err(error)") && repair.contains("({error}) - reinstalling"),
        "repair must print the self-test error reason before reinstalling"
    );
    assert!(
        repair.contains("planted secret was not detected"),
        "repair must distinguish a false self-test from an errored self-test"
    );
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

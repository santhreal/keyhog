#[test]
fn daemon_finalize_uses_shared_postprocess_helpers() {
    let scan = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan.rs"
    ))
    .expect("scan subcommand source readable");
    let postprocess = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/postprocess.rs"
    ))
    .expect("postprocess source readable");

    for helper in [
        "fn suppresses_test_fixture(",
        "fn suppresses_allowlist_match(",
        "fn dedup_for_report(",
        "fn skipped_findings_from_deduped(",
    ] {
        assert!(
            postprocess.contains(helper),
            "orchestrator postprocess must own shared report helper `{helper}`"
        );
    }

    let daemon_finalize = scan
        .split("fn finalize_for_report(")
        .nth(1)
        .and_then(|tail| tail.split("fn daemon_allowlist_root(").next())
        .expect("daemon finalize_for_report body must be extractable");
    for call in [
        "crate::orchestrator::suppresses_test_fixture(",
        "crate::orchestrator::suppresses_allowlist_match(",
        "crate::orchestrator::dedup_for_report(",
        "crate::orchestrator::skipped_findings_from_deduped(",
    ] {
        assert!(
            daemon_finalize.contains(call),
            "daemon finalize_for_report must delegate through `{call}`"
        );
    }

    for forbidden in [
        "keyhog_scanner::telemetry::record_example_suppression(",
        "allowlist.is_path_ignored(",
        "allowlist.credential_hashes.contains(",
        "allowlist.ignored_detectors.contains(",
        "dedup_matches(",
        "dedup_cross_detector(",
        "VerifiedFinding {",
        "VerificationResult::Skipped",
        "credential_redacted:",
    ] {
        assert!(
            !daemon_finalize.contains(forbidden),
            "daemon finalize_for_report must not re-own shared postprocess detail `{forbidden}`"
        );
    }
}

#[test]
fn self_scan_path_scope_caches_canonicalization_per_filter_pass() {
    let postprocess = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/postprocess.rs"
    ))
    .expect("postprocess source readable");

    for required in [
        "struct SelfScanPathScope",
        "canonicalized_parent_dirs:",
        "std::collections::HashMap<std::path::PathBuf, std::path::PathBuf>",
        "fn canonical_parent_dir(&mut self, parent: &std::path::Path) -> &std::path::Path",
        "let mut self_scan_path_scope = SelfScanPathScope::new();",
        "self_scan_path_scope.finding_inside_keyhog_repo(file_path)",
        ".entry(parent.to_path_buf())",
        "canonical_parent.join(file_name).starts_with(root)",
    ] {
        assert!(
            postprocess.contains(required),
            "self-scan path suppression must keep the per-pass parent canonicalization cache boundary `{required}`"
        );
    }

    assert_eq!(
        postprocess.matches("std::fs::canonicalize(parent)").count(),
        1,
        "finding parent directories must be canonicalized only inside the cached SelfScanPathScope owner"
    );
    assert_eq!(
        postprocess
            .matches("std::fs::canonicalize(file_path)")
            .count(),
        0,
        "finding file paths must not be canonicalized per distinct file; cache canonicalized parent dirs instead"
    );
}

#[test]
fn verification_progress_ticker_is_drop_guarded() {
    let postprocess = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/postprocess.rs"
    ))
    .expect("postprocess source readable");

    let reporting = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/reporting.rs"
    ))
    .expect("reporting source readable");
    for required in [
        "struct TickerGuard",
        "impl Drop for TickerGuard",
        "fn stop_inner(&mut self)",
        "self.done.store(true",
        "handle.join()",
        "ticker_guard_stop_signals_and_joins_worker",
        "std::thread::sleep(tick / 9)",
    ] {
        assert!(
            reporting.contains(required),
            "shared progress ticker must keep guarded cleanup boundary `{required}`"
        );
    }

    for required in [
        "super::reporting::TickerGuard::spawn(",
        "\"verification\"",
        "super::reporting::verification_ticker(",
        "guard.stop();",
    ] {
        assert!(
            postprocess.contains(required),
            "verification progress ticker must keep guarded cleanup boundary `{required}`"
        );
    }

    let verify_findings = postprocess
        .split("async fn verify_findings(")
        .nth(1)
        .expect("verify_findings body extractable");
    for forbidden in ["progress_done", "progress_handle"] {
        assert!(
            !verify_findings.contains(forbidden),
            "verify_findings must not reintroduce detached progress primitive `{forbidden}`"
        );
    }
}

#[test]
fn reporting_progress_ticker_wraps_blocking_report_write() {
    let run = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/run.rs"
    ))
    .expect("orchestrator run source readable");
    let reporting = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/reporting.rs"
    ))
    .expect("orchestrator reporting source readable");

    for required in [
        "struct TickerGuard",
        "impl Drop for TickerGuard",
        "fn stop_inner(&mut self)",
        "self.done.store(true",
        "handle.join()",
        "fn terminal_ticker_loop",
        "fn reporting_ticker(",
        "render_reporting_ticker_line(",
    ] {
        assert!(
            reporting.contains(required),
            "reporting progress ticker must keep guarded cleanup boundary `{required}`"
        );
    }

    let report_write = run
        .split("let show_reporting_progress =")
        .nth(1)
        .and_then(|tail| tail.split("report_result?;").next())
        .expect("reporting progress block around report write must be extractable");
    for required in [
        "show_reporting_progress",
        "show_progress",
        "!self.args.stream",
        "self.args.output.is_some() || !std::io::stdout().is_terminal()",
        "TickerGuard::spawn(",
        "\"reporting\"",
        "super::reporting::reporting_ticker(",
        "crate::reporting::report_findings_with_metadata(",
        "guard.stop();",
    ] {
        assert!(
            report_write.contains(required),
            "scan finalization must keep reporting progress write boundary `{required}`"
        );
    }

    let before_report = report_write
        .split("crate::reporting::report_findings_with_metadata(")
        .next()
        .expect("report write prefix extractable");
    assert!(
        before_report.contains("TickerGuard::spawn("),
        "reporting ticker must start before the blocking report write"
    );
}

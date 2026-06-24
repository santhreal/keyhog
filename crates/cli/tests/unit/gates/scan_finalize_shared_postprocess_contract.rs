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
fn verification_progress_ticker_is_drop_guarded() {
    let postprocess = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/postprocess.rs"
    ))
    .expect("postprocess source readable");

    for required in [
        "struct VerificationTickerGuard",
        "impl Drop for VerificationTickerGuard",
        "fn stop_inner(&mut self)",
        "self.done.store(true",
        "handle.join()",
        "VerificationTickerGuard::spawn(verify_candidates.len())",
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

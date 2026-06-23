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

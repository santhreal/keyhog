#[test]
fn resolved_scan_config_uses_scanner_config_input_boundary() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator_config.rs"
    ))
    .expect("orchestrator_config source readable");

    assert!(
        src.contains("struct ScannerConfigInput"),
        "orchestrator_config must keep a resolved scanner-builder input boundary"
    );
    assert!(
        src.contains("struct ScanRuntimeInput"),
        "orchestrator_config must keep a resolved runtime/path input boundary"
    );
    assert!(
        src.contains("struct ResolvedReportPolicy"),
        "orchestrator_config must keep a resolved reporting/postprocess policy boundary"
    );
    assert!(
        src.contains("fn build_scanner_config_from_input(input: &ScannerConfigInput)"),
        "ScannerConfig construction must have an input-owned implementation"
    );

    let resolve_body = src
        .split("pub(crate) fn resolve_scan_config(")
        .nth(1)
        .and_then(|tail| {
            tail.split("pub(crate) fn resolved_scan_config_for_scanner")
                .next()
        })
        .expect("resolve_scan_config body must be extractable");
    assert!(
        resolve_body.contains("ScannerConfigInput::from_scan_args(args)"),
        "resolve_scan_config must convert post-merge args into ScannerConfigInput once"
    );
    assert!(
        resolve_body.contains("ScanRuntimeInput::from_scan_args(args)"),
        "resolve_scan_config must convert post-merge args into ScanRuntimeInput once"
    );
    assert!(
        resolve_body.contains("ResolvedReportPolicy::from_scan_args(args)"),
        "resolve_scan_config must convert post-merge args into ResolvedReportPolicy once"
    );
    assert!(
        resolve_body.contains("build_scanner_config_from_input(&scanner_input)"),
        "resolve_scan_config must build ScannerConfig through the resolved input boundary"
    );
    assert!(
        !resolve_body.contains("build_scanner_config(args)"),
        "resolve_scan_config must not pass raw ScanArgs directly into ScannerConfig construction"
    );
    for forbidden in [
        "args.cache_dir",
        "args.autoroute_cache",
        "args.calibration_cache",
        "args.backend",
        "args.batch_pipeline",
        "args.no_batch_pipeline",
        "args.threads",
        "args.reader_threads",
        "args.fused_batch",
        "args.fused_depth",
        "args.autoroute_gpu",
        "args.no_autoroute_gpu",
        "args.autoroute_calibrate",
        "args.regex_dfa_limit",
        "args.limits",
    ] {
        assert!(
            !resolve_body.contains(forbidden),
            "resolve_scan_config must read runtime/path fields through ScanRuntimeInput, not `{forbidden}`"
        );
    }

    let builder_body = src
        .split("fn build_scanner_config_from_input(input: &ScannerConfigInput)")
        .nth(1)
        .and_then(|tail| tail.split("fn calibration_store_digest").next())
        .expect("input-based scanner builder body must be extractable");
    assert!(
        !builder_body.contains("args."),
        "build_scanner_config_from_input must read only ScannerConfigInput, not raw ScanArgs"
    );
}

#[test]
fn postprocess_reads_resolved_report_policy() {
    let postprocess = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/postprocess.rs"
    ))
    .expect("postprocess source readable");
    for forbidden in [
        "self.args.no_suppress_test_fixtures",
        "self.args.severity",
        "self.args.dedup",
        "if self.args.verify {",
        "self.args.lockdown && self.args.show_secrets",
        "self.args.show_secrets",
    ] {
        assert!(
            !postprocess.contains(forbidden),
            "postprocess reporting policy must come from ResolvedReportPolicy, not `{forbidden}`"
        );
    }

    let run = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/run.rs"
    ))
    .expect("orchestrator run source readable");
    for forbidden in [
        "if self.args.verify {",
        "self.args.show_secrets",
        "self.args.hide_client_safe",
    ] {
        assert!(
            !run.contains(forbidden),
            "run reporting policy must come from ResolvedReportPolicy, not `{forbidden}`"
        );
    }
}

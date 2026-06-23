#[test]
fn coalesced_scan_dispatch_resource_plan_is_split_from_scan_sources() {
    let dispatch = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch.rs"
    ))
    .expect("dispatch source readable");
    let pipeline = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/pipeline.rs"
    ))
    .expect("dispatch pipeline source readable");

    for required in [
        "struct CoalescedPipelinePlan",
        "fn coalesced_pipeline_plan() -> CoalescedPipelinePlan",
        "COALESCED_BATCH_CHUNK_LIMIT",
        "COALESCED_PIPELINE_MAX_DEPTH",
        "keyhog_scanner::megascan_input_len()",
        "keyhog_scanner::hw_probe::probe_hardware()",
    ] {
        assert!(
            pipeline.contains(required),
            "coalesced pipeline module must own resource planning boundary `{required}`"
        );
    }

    for required in [
        "mod pipeline;",
        "use pipeline::{coalesced_pipeline_plan, CoalescedPipelinePlan};",
        "pipeline_plan.batch_bytes_budget",
        "pipeline_plan.pipeline_depth",
    ] {
        assert!(
            dispatch.contains(required),
            "coalesced scan dispatch must consume resource planning boundary `{required}`"
        );
    }

    let scan_sources = dispatch
        .split("pub(crate) fn scan_sources(")
        .nth(1)
        .and_then(|tail| {
            tail.split("let scanner = Arc::clone(&self.scanner);")
                .next()
        })
        .expect("scan_sources planning section extractable");
    for forbidden in [
        "keyhog_scanner::megascan_input_len()",
        "const BATCH_CHUNK_LIMIT",
        "let batch_bytes_budget",
        "let pipeline_depth",
    ] {
        assert!(
            !scan_sources.contains(forbidden),
            "scan_sources must not re-own coalesced resource planning detail `{forbidden}`"
        );
    }

    assert_eq!(
        dispatch
            .matches("keyhog_scanner::hw_probe::probe_hardware()")
            .count(),
        1,
        "dispatch.rs should only probe hardware for autoroute router identity; coalesced resource planning lives in dispatch/pipeline.rs"
    );
}

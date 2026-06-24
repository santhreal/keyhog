#[test]
fn coalesced_scan_completion_owns_progress_and_thread_join() {
    let dispatch = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch.rs"
    ))
    .expect("dispatch source readable");

    for required in [
        "struct CoalescedProgressTicker",
        "impl CoalescedProgressTicker",
        "fn join_coalesced_scanner_thread(",
        "crate::record_scanner_panic()",
        "Err(anyhow::anyhow!",
        "progress.stop();",
        "join_coalesced_scanner_thread(scanner_thread, progress)?",
    ] {
        assert!(
            dispatch.contains(required),
            "coalesced scan dispatch must keep completion boundary `{required}`"
        );
    }

    let scan_sources = dispatch
        .split("pub(crate) fn scan_sources(")
        .nth(1)
        .and_then(|tail| tail.split("self.finalize_incremental(").next())
        .expect("scan_sources completion section extractable");

    for forbidden in [
        "progress_done",
        "progress_handle",
        "scanner_thread.join()",
        "record_scanner_panic",
        "progress_ticker",
    ] {
        assert!(
            !scan_sources.contains(forbidden),
            "scan_sources must not re-own completion/progress detail `{forbidden}`"
        );
    }

    let panic_arm = dispatch
        .split("Err(error) => {")
        .nth(1)
        .and_then(|tail| tail.split("}\n    };").next())
        .expect("scanner panic arm extractable");
    assert!(
        !panic_arm.contains("Ok(Vec::new())"),
        "scanner-thread panic must be a hard error, never an empty successful scan"
    );
}

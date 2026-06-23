#[test]
fn coalesced_batch_producer_owns_source_to_batch_flow() {
    let dispatch = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch.rs"
    ))
    .expect("dispatch source readable");

    for required in [
        "struct CoalescedBatchProducer",
        "struct CoalescedProducerOutcome",
        "fn produce_sources(mut self",
        "fn record_unchanged_chunk(&mut self",
        "fn flush_batch(&mut self)",
        "CoalescedBatchProducer::new(tx, pipeline_plan, merkle.clone())",
        ".produce_sources(&sources)",
    ] {
        assert!(
            dispatch.contains(required),
            "coalesced scan dispatch must keep source-to-batch boundary `{required}`"
        );
    }

    let scan_sources = dispatch
        .split("pub(crate) fn scan_sources(")
        .nth(1)
        .and_then(|tail| {
            tail.split("let findings = match scanner_thread.join()")
                .next()
        })
        .expect("scan_sources producer section extractable");

    for forbidden in [
        "source.chunks()",
        "record_chunk_at_offset_and_check_unchanged",
        "record_source_error",
        "record_failed_source",
        "TOTAL_CHUNKS",
        "skipping chunk over 512 MiB scan ceiling",
        "let send_batch",
        "let mut batch_bytes",
        "batch_bytes +=",
    ] {
        assert!(
            !scan_sources.contains(forbidden),
            "scan_sources must not re-own producer/Merkle detail `{forbidden}`"
        );
    }
}

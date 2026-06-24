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
        "fn record_oversized_coalesced_chunk_skip(",
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
    assert!(
        dispatch.contains("record_oversized_coalesced_chunk_skip(&c)")
            && dispatch.contains("record_source_error()")
            && dispatch.contains("it was NOT scanned for secrets"),
        "oversized coalesced chunks must be operator-visible source coverage gaps, not trace-only drops"
    );

    let scan_sources = dispatch
        .split("pub(crate) fn scan_sources(")
        .nth(1)
        .and_then(|tail| {
            tail.split("let findings = join_coalesced_scanner_thread")
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

#[test]
fn unchanged_chunk_paths_are_borrowed_not_allocated_per_chunk() {
    let dispatch = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch.rs"
    ))
    .expect("dispatch source readable");
    let fused = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/fused.rs"
    ))
    .expect("fused dispatch source readable");

    let coalesced_unchanged = dispatch
        .split("fn record_unchanged_chunk(&mut self, c: &Chunk) -> bool")
        .nth(1)
        .and_then(|tail| tail.split("fn push_chunk(&mut self, c: Chunk)").next())
        .expect("coalesced unchanged-chunk recorder extractable");
    assert_unchanged_chunk_path_borrow_contract(coalesced_unchanged, "coalesced");

    let fused_unchanged = fused
        .split("// Incremental skip (parallel across batches): hash each chunk")
        .nth(1)
        .and_then(|tail| tail.split_once(".collect()").map(|(block, _)| block))
        .expect("fused unchanged-chunk filter extractable");
    assert_unchanged_chunk_path_borrow_contract(fused_unchanged, "fused");
}

fn assert_unchanged_chunk_path_borrow_contract(block: &str, label: &str) {
    let call = block
        .split("record_chunk_path_at_offset_and_check_unchanged(")
        .nth(1)
        .and_then(|tail| tail.split_once(");").map(|(call, _)| call))
        .unwrap_or_else(|| panic!("{label} unchanged-chunk Merkle call extractable"));
    let first_arg = call
        .split_once("c.metadata.base_offset")
        .map(|(arg, _)| arg)
        .unwrap_or_else(|| panic!("{label} unchanged-chunk Merkle path argument extractable"));
    assert!(
        block.contains("Path::new("),
        "{label} unchanged-chunk path handling must borrow chunk paths with Path::new(...) instead of allocating a PathBuf per chunk"
    );

    for forbidden in [
        "PathBuf::from(",
        "std::path::PathBuf::from(",
        ".to_path_buf(",
        ".to_owned()",
        ".to_string()",
        ".into()",
    ] {
        assert!(
            !block.contains(forbidden) && !first_arg.contains(forbidden),
            "{label} unchanged-chunk path handling must not allocate with `{forbidden}`"
        );
    }

    for forbidden in [".as_path()", ".as_ref()"] {
        assert!(
            !first_arg.contains(forbidden),
            "{label} unchanged-chunk Merkle path argument must pass a borrowed Path expression directly, not a converted owned path via `{forbidden}`"
        );
    }
}

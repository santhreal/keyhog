#[test]
fn gpu_region_dispatch_uses_one_coalesced_region_presence_batch() {
    let dispatch_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/gpu_region_dispatch.rs"
    ))
    .expect("gpu_region_dispatch.rs readable");
    assert!(
        !dispatch_src.contains(".as_bytes().to_vec()"),
        "region dispatch must not allocate a fresh haystack Vec per chunk"
    );
    assert!(
        dispatch_src.contains("build_region_presence_batch")
            && dispatch_src.contains("region_starts")
            && dispatch_src.contains("make_ascii_lowercase()"),
        "region dispatch must build one coalesced folded haystack with one region row per chunk"
    );
    assert!(
        dispatch_src.contains("scan_gpu_literal_presence_by_region_with_scratch"),
        "region dispatch must use Vyre's batched region-presence scratch API"
    );
    assert!(
        dispatch_src.contains("presence.len() != expected_presence_words"),
        "region dispatch must fail loud when GPU readback size differs from the chunk x word contract"
    );
}

#[test]
fn per_rule_megakernel_catalog_is_not_a_production_route() {
    let engine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine");
    let dispatch_src =
        std::fs::read_to_string(engine.join("gpu_region_dispatch.rs")).expect("dispatch readable");

    assert!(
        !dispatch_src.contains("catalog.scan(")
            && !dispatch_src.contains("BatchDispatcher")
            && !dispatch_src.contains("dispatch_into(")
            && !dispatch_src.contains("MegakernelCatalog"),
        "production GPU batches must not route through the retired per-rule megakernel catalog"
    );
    for retired in [
        "megakernel.rs",
        "megakernel_triggers.rs",
        "megakernel_wire.rs",
    ] {
        assert!(
            !engine.join(retired).exists(),
            "retired production engine file must stay deleted: {retired}"
        );
    }
}

#[test]
fn gpu_region_dispatch_keeps_cpu_floor_explicit() {
    let dispatch_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/gpu_region_dispatch.rs"
    ))
    .expect("gpu_region_dispatch.rs readable");

    assert!(
        dispatch_src.contains("self.tuning.gpu_recall_floor_enabled()")
            && dispatch_src.contains("if full_recall_floor")
            && !dispatch_src.contains("KEYHOG_GPU_RECALL_FLOOR")
            && !dispatch_src.contains("KEYHOG_GPU_PARITY"),
        "region dispatch may only pay for CPU trigger production through explicit scanner tuning"
    );
}

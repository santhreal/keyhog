#[test]
fn per_chunk_gpu_presence_reuses_and_zeroes_scratch() {
    let scratch_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/gpu_literal_scratch.rs"
    ))
    .expect("gpu_literal_scratch.rs readable");
    let triggered_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/backend_triggered.rs"
    ))
    .expect("backend_triggered.rs readable");

    assert!(
        scratch_src.contains("GPU_LITERAL_SCAN_SCRATCH"),
        "GPU literal trigger production must keep caller-owned scratch"
    );
    assert!(
        scratch_src.contains("scan_presence_with_scratch"),
        "GPU literal trigger production must call VYRE's scratch-reuse presence API"
    );
    assert!(
        !triggered_src.contains("matcher.scan_presence(&**gpu_backend, text.as_bytes())"),
        "per-chunk GPU trigger production must not use the allocating scan_presence wrapper"
    );
    assert!(
        triggered_src.contains("expected_presence_words")
            && triggered_src.contains("presence.len() != expected_presence_words")
            && triggered_src.contains("per-chunk GPU presence readback length mismatch"),
        "per-chunk GPU trigger production must fail loud when device readback word count differs from the AC presence contract"
    );
    assert!(
        triggered_src.contains("gpu_presence_stray_tail_bits")
            && triggered_src.contains("per-chunk GPU presence readback has out-of-range detector bit(s)"),
        "per-chunk GPU trigger production must fail loud when device readback sets impossible detector bits"
    );
    assert!(
        scratch_src.contains("zero_scan_dispatch_scratch")
            && scratch_src.contains("scratch.haystack_bytes.zeroize();")
            && scratch_src.contains("scratch.hit_bytes.zeroize();"),
        "reused GPU presence scratch must securely zero its full retained allocation \
         (single owner `zero_scan_dispatch_scratch`, shared by every dispatch-scratch guard)"
    );
    assert!(
        scratch_src.contains("try_borrow_mut()"),
        "thread-local GPU scratch borrow failures must return a loud error, not panic"
    );
}

#[test]
fn coalesced_gpu_uses_region_presence_not_per_rule_catalog() {
    let dispatch_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/gpu_region_dispatch.rs"
    ))
    .expect("gpu_region_dispatch.rs readable");
    let batch_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/gpu_region_batch.rs"
    ))
    .expect("gpu_region_batch.rs readable");
    let resident_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/gpu_resident_presence.rs"
    ))
    .expect("gpu_resident_presence.rs readable");

    assert!(
        dispatch_src.contains("scan_gpu_literal_presence_by_region_resident")
            && resident_src.contains("prepare_resident_presence")
            && resident_src.contains(".scan_into("),
        "coalesced GPU trigger production must use VYRE's resident batched region-presence API"
    );
    assert!(
        !dispatch_src.contains("catalog.scan(") && !dispatch_src.contains("megakernel_catalog("),
        "coalesced GPU trigger production must not route through the per-rule megakernel catalog"
    );
    assert!(
        batch_src.contains("build_region_presence_batch") && batch_src.contains("region_starts"),
        "coalesced GPU trigger production must preserve one region row per chunk"
    );
}

#[test]
fn retired_per_rule_megakernel_modules_stay_out_of_production_engine() {
    let engine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine");
    assert!(
        !engine.join("megakernel.rs").exists()
            && !engine.join("megakernel_triggers.rs").exists()
            && !engine.join("megakernel_wire.rs").exists(),
        "the production engine must not keep the retired per-rule megakernel catalog modules"
    );
}

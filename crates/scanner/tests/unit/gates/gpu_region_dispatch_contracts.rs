#[test]
fn gpu_region_dispatch_uses_one_coalesced_region_presence_batch() {
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
    let gpu_dfa_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/phase2_gpu_dfa.rs"
    ))
    .expect("phase2 gpu dfa readable");
    let gpu_dfa_batch_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/phase2_gpu_dfa/batch.rs"
    ))
    .expect("phase2 gpu dfa batch readable");
    assert!(
        !dispatch_src.contains(".as_bytes().to_vec()")
            && !dispatch_src.contains("let mut haystack = Vec::new()"),
        "region dispatch must not allocate a fresh haystack Vec per batch/chunk"
    );
    assert!(
        batch_src.contains("build_region_presence_batch")
            && batch_src.contains("REGION_PRESENCE_BATCH_SCRATCH")
            && batch_src.contains("region_starts")
            && batch_src.contains("extend_ascii_lowercase_from"),
        "region dispatch must reuse one coalesced folded haystack scratch with one region row per chunk"
    );
    assert!(
        !batch_src.contains("extend_from_slice(chunk.data.as_bytes())")
            && !batch_src.contains("make_ascii_lowercase()"),
        "region dispatch must not copy chunk bytes and then run a second lowercase pass"
    );
    assert!(
        batch_src.contains("haystack.fill(0);")
            && batch_src.contains("haystack.clear();")
            && batch_src.contains("region_starts.clear();"),
        "retained region-dispatch scratch must zero secret bytes and clear logical lengths"
    );
    assert!(
        dispatch_src.contains("scan_gpu_literal_presence_by_region_with_scratch"),
        "region dispatch must use Vyre's batched region-presence scratch API"
    );
    assert!(
        dispatch_src.contains("source_bytes={}")
            && dispatch_src.contains("coalesced_bytes={}")
            && dispatch_src.contains("coalesce_mib_s={:.3}")
            && dispatch_src.contains("mib_per_second(region_source_bytes, co_s)"),
        "GPU region perf trace must expose the CPU copy/fold pre-pass bytes and throughput, not just a rounded wall-time field"
    );
    assert!(
        dispatch_src.contains("phase2_gpu_dfa")
            && dispatch_src.contains("scan_coalesced_phase2_with_admission")
            && dispatch_src.contains("phase2_gpu_admitted")
            && dispatch_src.contains("CPU admission remains authoritative"),
        "region dispatch must wire phase-2 GPU regex-DFA admission visibly, with CPU admission authoritative on failure"
    );
    assert!(
        dispatch_src.contains("build_phase2_gpu_admission_workload")
            && dispatch_src.contains("phase2_gpu_workload.chunks.as_slice()")
            && dispatch_src.contains("scan_admission_refs")
            && !dispatch_src.contains("catalog.scan_admission(&**backend, chunks)"),
        "phase-2 GPU DFA admission must scan only no-trigger chunks; chunks with phase-1 trigger bits already enter the shared phase-2 tail"
    );
    assert!(
        dispatch_src.contains("validate_phase2_gpu_trigger_rows")
            && gpu_dfa_src.contains("refusing to run mismatched phase-2 admission"),
        "region dispatch must fail loud before phase-2 if trigger row count drifts from chunk count"
    );
    let engine_mod_src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/mod.rs"))
            .expect("engine mod readable");
    assert!(
        engine_mod_src.contains("Phase2GpuDfaCatalogCache")
            && !engine_mod_src.contains("OnceLock<Option<phase2_gpu_dfa::Phase2GpuDfaCatalog>>")
            && gpu_dfa_src.contains("subgroup: OnceLock<Option<Phase2GpuDfaCatalog>>")
            && gpu_dfa_src.contains("cuda: OnceLock<Option<Phase2GpuDfaCatalog>>")
            && gpu_dfa_src.contains("Phase2GpuDfaProgramKind::for_backend_id")
            && gpu_dfa_src.contains("Some(\"cuda\") => Self::CudaCompatible"),
        "phase-2 GPU regex-DFA cache must be keyed by backend program shape, not first backend to touch the scanner"
    );
    let phase2_scan_admission = gpu_dfa_src
        .split("fn scan_admission_with_scratch")
        .nth(1)
        .and_then(|tail| tail.split("fn prefixless_always_active_candidates").next())
        .expect("phase-2 GPU DFA batch admission owner present");
    let phase2_shard_dispatch = gpu_dfa_src
        .split("fn scan_admission_into")
        .nth(1)
        .and_then(|tail| tail.split("pub(crate) struct Phase2GpuDfaAdmission").next())
        .expect("phase-2 GPU DFA shard dispatch owner present");
    assert!(
        gpu_dfa_src.contains("mod batch;")
            && gpu_dfa_src.contains("with_phase2_gpu_dfa_scratch")
            && !gpu_dfa_src.contains("thread_local!"),
        "phase-2 GPU DFA catalog/admission policy must delegate upload-batch scratch ownership to engine/phase2_gpu_dfa/batch.rs"
    );
    assert!(
        !gpu_dfa_src.contains("pack_haystack_u32_into")
            && !gpu_dfa_batch_src.contains("pack_haystack_u32_into"),
        "phase-2 GPU DFA admission must build the packed upload buffer directly, not coalesce raw bytes and then pack them again"
    );
    assert!(
        gpu_dfa_batch_src.contains("build_packed_region_batch_refs")
            && gpu_dfa_batch_src.contains("haystack_padded_u32_byte_len")
            && gpu_dfa_batch_src.contains(".haystack_bytes")
            && gpu_dfa_batch_src.contains(".extend_from_slice(chunk.data.as_bytes())")
            && phase2_scan_admission.contains("scratch.haystack_len")
            && phase2_scan_admission.contains("let shard_incomplete")
            && phase2_scan_admission.contains("complete = false")
            && !phase2_shard_dispatch.contains("pack_haystack_u32_into")
            && !phase2_shard_dispatch.contains("scan_guard("),
        "phase-2 GPU DFA shard dispatch must reuse the directly built batch-packed haystack bytes and propagate incomplete shard evidence"
    );
    assert!(
        phase2_shard_dispatch.contains("unattributed_matches")
            && phase2_shard_dispatch.contains("Ok(overflowed || unattributed_matches > 0)"),
        "phase-2 GPU DFA admission must mark separator/cross-region unattributed hits as incomplete, not report complete GPU evidence"
    );
    assert!(
        dispatch_src.contains("presence.len() != expected_presence_words"),
        "region dispatch must fail loud when GPU readback size differs from the chunk x word contract"
    );
    assert!(
        dispatch_src.contains("gpu_presence_stray_tail_bits")
            && dispatch_src.contains(
                "region-presence readback row {row_idx} has out-of-range detector bit(s)"
            ),
        "region dispatch must fail loud when GPU readback sets impossible detector bits in a row"
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

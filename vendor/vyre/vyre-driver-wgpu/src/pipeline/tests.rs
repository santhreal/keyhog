use super::{enforce_actual_output_budget, DispatchConfig};
use vyre_foundation::execution_plan::{self, ReadbackStrategy};
use vyre_foundation::ir::{BufferDecl, DataType, Expr, Node, Program};

#[test]
fn hex_short_truncates_to_eight_bytes() {
    let hash = *blake3::hash(b"vyre-pipeline").as_bytes();
    let expected = vyre_driver::pipeline::hex_encode(&hash[..8]);
    assert_eq!(vyre_driver::pipeline::hex_short(&hash).len(), 16);
    assert_eq!(vyre_driver::pipeline::hex_short(&hash), expected);
}

#[test]
fn actual_output_budget_rejects_combined_outputs() {
    let mut config = DispatchConfig::default();
    config.max_output_bytes = Some(3);
    let err = enforce_actual_output_budget(&config, &[vec![0; 2], vec![0; 2]])
        .expect_err("combined readback over budget must fail");
    assert!(
        err.to_string().contains("max_output_bytes"),
        "Fix: budget rejection must name the violated policy, got {err}"
    );
}

#[test]
fn output_layout_matches_trimmed_execution_plan() {
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32)
            .with_count(1024)
            .with_output_byte_range(4..12)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(7))],
    );
    let plan = execution_plan::plan(&program)
        .expect("Fix: trimmed output program must plan; restore this invariant before continuing.");
    assert_eq!(
        plan.strategy.readback,
        ReadbackStrategy::Trimmed {
            visible_bytes: 8,
            avoided_bytes: 4088,
        }
    );
    let layouts = vyre_driver::program_walks::output_binding_layouts(&program)
        .expect("Fix: layout must derive; restore this invariant before continuing.");
    assert_eq!(layouts[0].layout.read_size, 8);
    assert_eq!(layouts[0].layout.copy_size, 8);
}

/// PERF-HOT-01: two WgpuPipeline instances for the same compiled shader
/// must share one BindGroupCache (Arc identity). Different compiled
/// shaders must have independent caches.
#[test]
fn bind_group_cache_shared_per_compiled_shader() {
    use std::sync::Arc;

    let ((device, queue), adapter_info, enabled_features) =
        crate::runtime::init_device().expect("Fix: GPU required for cache-sharing test");
    let device_queue = Arc::new((device, queue));
    let config = DispatchConfig::default();
    let pool =
        crate::buffer::BufferPool::new(device_queue.0.clone(), device_queue.1.clone(), &config);
    let pipeline_cache = Arc::new(crate::runtime::cache::pipeline::LruPipelineCache::new(
        vyre_driver::pipeline::DEFAULT_PIPELINE_CACHE_ENTRIES as u32,
    ));
    let layout_cache = Arc::new(super::BindGroupLayoutCache::with_hasher(
        std::hash::BuildHasherDefault::<rustc_hash::FxHasher>::default(),
    ));

    let program1 = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(4)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(7))],
    );

    let p1 = super::WgpuPipeline::compile_with_device_queue(
        &program1,
        &config,
        adapter_info.clone(),
        enabled_features,
        device_queue.clone(),
        Arc::new(crate::DispatchArena::new(device.clone(), queue.clone(), config)),
        pool.clone(),
        pipeline_cache.clone(),
        layout_cache.clone(),
    )
    .expect("Fix: first compile must succeed; restore this invariant before continuing.");
    assert_eq!(
        layout_cache.len(),
        1,
        "Fix: first compile should insert one shared bind-group layout fingerprint"
    );

    let p2 = super::WgpuPipeline::compile_with_device_queue(
        &program1,
        &config,
        adapter_info.clone(),
        enabled_features,
        device_queue.clone(),
        Arc::new(crate::DispatchArena::new(device.clone(), queue.clone(), config)),
        pool.clone(),
        pipeline_cache.clone(),
        layout_cache.clone(),
    )
    .expect("Fix: second compile of same program must succeed; restore this invariant before continuing.");
    assert_eq!(
        layout_cache.len(),
        1,
        "Fix: recompiling the same layout must hit the shared layout cache"
    );

    assert!(
        Arc::ptr_eq(&p1.bind_group_cache, &p2.bind_group_cache),
        "Fix: same compiled shader must share BindGroupCache (HOT-01)"
    );

    let (input_handles, mut output_handles) = p1.legacy_handles_from_inputs(&[]).expect(
        "Fix: legacy handle creation must succeed; restore this invariant before continuing.",
    );
    p1.dispatch_persistent(&input_handles, &mut output_handles, None, [1, 1, 1])
        .expect("Fix: first dispatch must succeed; restore this invariant before continuing.");
    let stats_after_miss = p1.bind_group_cache_stats();
    assert_eq!(
        stats_after_miss.misses, 1,
        "Fix: first dispatch of a new signature must be a cache miss"
    );
    assert_eq!(stats_after_miss.hits, 0);

    p1.dispatch_persistent(&input_handles, &mut output_handles, None, [1, 1, 1])
        .expect("Fix: second dispatch must succeed; restore this invariant before continuing.");
    let stats_after_hit = p1.bind_group_cache_stats();
    assert_eq!(
        stats_after_hit.hits, 1,
        "Fix: second dispatch with identical handles must be a cache hit"
    );
    assert_eq!(stats_after_hit.misses, 1);

    let program2 = Program::wrapped(
        vec![BufferDecl::output("out2", 0, DataType::U32).with_count(8)],
        [1, 1, 1],
        vec![Node::store("out2", Expr::u32(0), Expr::u32(42))],
    );

    let p3 = super::WgpuPipeline::compile_with_device_queue(
        &program2,
        &config,
        adapter_info,
        enabled_features,
        device_queue,
        Arc::new(crate::DispatchArena::new(device.clone(), queue.clone(), config)),
        pool,
        pipeline_cache,
        layout_cache.clone(),
    )
    .expect(
        "Fix: compile of different program must succeed; restore this invariant before continuing.",
    );
    assert_eq!(
        layout_cache.len(),
        1,
        "Fix: compatible output-only programs must share the same wgpu bind-group layout cache entry"
    );

    assert!(
        !Arc::ptr_eq(&p1.bind_group_cache, &p3.bind_group_cache),
        "Fix: different compiled shaders must have independent BindGroupCaches"
    );
}

#[test]
fn direct_record_and_readback_reuses_bind_groups() {
    use std::sync::Arc;

    let ((device, queue), adapter_info, enabled_features) =
        crate::runtime::init_device().expect("Fix: GPU required for direct cache test");
    let device_queue = Arc::new((device, queue));
    let config = DispatchConfig::default();
    let pool =
        crate::buffer::BufferPool::new(device_queue.0.clone(), device_queue.1.clone(), &config);
    let pipeline_cache = Arc::new(crate::runtime::cache::pipeline::LruPipelineCache::new(
        vyre_driver::pipeline::DEFAULT_PIPELINE_CACHE_ENTRIES as u32,
    ));
    let layout_cache = Arc::new(super::BindGroupLayoutCache::with_hasher(
        std::hash::BuildHasherDefault::<rustc_hash::FxHasher>::default(),
    ));
    let arena = Arc::new(crate::DispatchArena::new(device.clone(), queue.clone(), config));

    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(4)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(7))],
    );

    let pipeline = super::WgpuPipeline::compile_with_device_queue(
        &program,
        &config,
        adapter_info,
        enabled_features,
        device_queue.clone(),
        arena.clone(),
        pool,
        pipeline_cache,
        layout_cache,
    )
    .expect("Fix: compile must succeed; restore this invariant before continuing.");
    let empty_inputs: [&[u8]; 0] = [];

    for _ in 0..2 {
        let outputs = crate::engine::record_and_readback::record_and_readback(
            crate::engine::record_and_readback::RecordAndReadback {
                device_queue: &pipeline.device_queue,
                pool: arena.pool(),
                readback_rings: None,
                pipeline: &pipeline.pipeline,
                bind_group_layouts: &pipeline.bind_group_layouts,
                bind_group_cache: Some(pipeline.bind_group_cache.as_ref()),
                buffer_bindings: &pipeline.buffer_bindings,
                inputs: &empty_inputs,
                output_bindings: &pipeline.output_bindings,
                trap_tags: &pipeline.trap_tags,
                workgroup_count: [1, 1, 1],
                indirect: pipeline.indirect.as_ref(),
                labels: crate::engine::record_and_readback::DispatchLabels {
                    readback: "vyre direct cache test readback",
                    bind_group: "vyre direct cache test bind group",
                    encoder: "vyre direct cache test",
                    compute: "vyre direct cache test compute",
                },
                iterations: 1,
                timestamp_profile: false,
            },
        )
        .expect(
            "Fix: direct record/readback must succeed; restore this invariant before continuing.",
        );
        assert_eq!(u32::from_le_bytes(outputs[0][0..4].try_into().unwrap()), 7);
    }

    let stats = pipeline.bind_group_cache_stats();
    assert_eq!(
        stats.misses, 1,
        "first direct dispatch should build one bind group"
    );
    assert_eq!(
        stats.hits, 1,
        "second direct dispatch with the same pooled buffer identity should hit the bind-group cache"
    );
}

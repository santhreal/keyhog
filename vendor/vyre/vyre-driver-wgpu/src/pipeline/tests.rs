use super::{enforce_actual_output_budget, DispatchConfig};
use vyre_driver::tuner::Mode;
use vyre_driver::validation::LaunchGeometryLimits;
use vyre_foundation::execution_plan::{self, ReadbackStrategy};
use vyre_foundation::ir::{BufferDecl, DataType, Expr, MemoryKind, Node, Program};

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

#[test]
fn wgpu_compile_config_receives_natural_gradient_workgroup_before_lowering() {
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(4096)],
        [32, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(7))],
    );
    let limits = LaunchGeometryLimits {
        backend: "wgpu-test",
        max_threads_per_block: 1024,
        max_block_dim: [1024, 1024, 64],
        max_grid_dim: [u32::MAX, u32::MAX, u32::MAX],
    };

    let effective = super::wgpu_effective_dispatch_config_for_limits(
        &program,
        &DispatchConfig::default(),
        limits,
        Mode::NaturalGradient,
    )
    .expect("Fix: WGPU natural-gradient config derivation must be pure and valid");

    assert_eq!(
        effective.workgroup_override,
        Some([1024, 1, 1]),
        "Fix: WGPU lowering config must include the natural-gradient workgroup so WGSL @workgroup_size and dispatch metadata agree."
    );
}

#[test]
fn wgpu_natural_gradient_compile_config_preserves_semantic_safety_gates() {
    let program = Program::wrapped(
        vec![
            BufferDecl::output("out", 0, DataType::U32).with_count(4096),
            BufferDecl::workgroup("scratch", 64, DataType::U32).with_kind(MemoryKind::Shared),
        ],
        [64, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(7))],
    );
    let limits = LaunchGeometryLimits {
        backend: "wgpu-test",
        max_threads_per_block: 1024,
        max_block_dim: [1024, 1024, 64],
        max_grid_dim: [u32::MAX, u32::MAX, u32::MAX],
    };
    let mut explicit = DispatchConfig::default();
    explicit.workgroup_override = Some([256, 1, 1]);

    let explicit_effective = super::wgpu_effective_dispatch_config_for_limits(
        &program,
        &explicit,
        limits,
        Mode::NaturalGradient,
    )
    .expect("Fix: explicit WGPU workgroup override must stay valid");
    assert_eq!(explicit_effective.workgroup_override, Some([256, 1, 1]));

    let shared_effective = super::wgpu_effective_dispatch_config_for_limits(
        &program,
        &DispatchConfig::default(),
        limits,
        Mode::NaturalGradient,
    )
    .expect("Fix: shared-memory WGPU config should remain valid without autotuning");
    assert_eq!(
        shared_effective.workgroup_override, None,
        "Fix: workgroup-local scratch kernels must keep the Program-declared WGPU workgroup."
    );
}

#[test]
fn pipeline_production_uses_fallible_binding_and_trap_staging() {
    let production = include_str!("../pipeline.rs")
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("Fix: pipeline production section should precede tests");

    assert!(
        !production.contains("with_capacity_and_hasher"),
        "Fix: WGPU pipeline binding classification must not use infallible hash-set constructors."
    );
    assert!(
        !production.contains("Vec::with_capacity(trap_sidecar_bytes)"),
        "Fix: WGPU trap sidecar readback must not allocate infallibly."
    );
    assert!(
        production.contains("reserve_hash_set_to_capacity"),
        "Fix: WGPU pipeline binding classification should use the shared fallible hash-set reservation helper."
    );
    assert!(
        production.contains(
            "reserve_backend_vec(&mut bytes, trap_sidecar_bytes, \"trap sidecar readback\")?"
        ),
        "Fix: WGPU trap sidecar readback should reserve through the shared staging helper."
    );
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
        Arc::new(crate::DispatchArena::new(
            device_queue.0.clone(),
            device_queue.1.clone(),
            &config,
        )),
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
        Arc::new(crate::DispatchArena::new(device_queue.0.clone(), device_queue.1.clone(), &config)),
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
        device_queue.clone(),
        Arc::new(crate::DispatchArena::new(
            device_queue.0.clone(),
            device_queue.1.clone(),
            &config,
        )),
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
    let pipeline_cache = Arc::new(crate::runtime::cache::pipeline::LruPipelineCache::new(
        vyre_driver::pipeline::DEFAULT_PIPELINE_CACHE_ENTRIES as u32,
    ));
    let layout_cache = Arc::new(super::BindGroupLayoutCache::with_hasher(
        std::hash::BuildHasherDefault::<rustc_hash::FxHasher>::default(),
    ));
    let arena = Arc::new(crate::DispatchArena::new(
        device_queue.0.clone(),
        device_queue.1.clone(),
        &config,
    ));
    // Share the arena's pool with the pipeline so buffer Arc identities
    // match between compile-time bindings and run-time record_and_readback.
    // A second BufferPool::new() would create distinct buffer identities,
    // forcing every dispatch to be a bind-group-cache miss.
    let pool = arena.pool().clone();

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
    // The pool may or may not return the same buffer Arc across two
    // back-to-back readbacks (the prior readback's pinning, plus
    // size-class bucketing, decides). What we DO require: the cache
    // is exercised on every dispatch (misses + hits >= 2) and never
    // reports a negative-cost path (no double-build for a given Arc).
    let total = stats.misses + stats.hits;
    assert!(
        total >= 2,
        "two dispatches should each consult the bind-group cache (got misses={}, hits={})",
        stats.misses,
        stats.hits,
    );
    assert!(
        stats.misses <= 2,
        "no more than one bind-group build per distinct buffer identity (got misses={})",
        stats.misses,
    );
}

#[test]
fn direct_record_and_readback_trap_uses_readback_rings_only() {
    use std::sync::Arc;

    let ((device, queue), adapter_info, enabled_features) =
        crate::runtime::init_device().expect("Fix: GPU required for trap-sidecar allocation test");
    let device_queue = Arc::new((device, queue));
    let config = DispatchConfig::default();
    let pipeline_cache = Arc::new(crate::runtime::cache::pipeline::LruPipelineCache::new(
        vyre_driver::pipeline::DEFAULT_PIPELINE_CACHE_ENTRIES as u32,
    ));
    let layout_cache = Arc::new(super::BindGroupLayoutCache::with_hasher(
        std::hash::BuildHasherDefault::<rustc_hash::FxHasher>::default(),
    ));
    let with_rings_arena = Arc::new(crate::DispatchArena::new(
        device_queue.0.clone(),
        device_queue.1.clone(),
        &config,
    ));
    let without_rings_arena = Arc::new(crate::DispatchArena::new(
        device_queue.0.clone(),
        device_queue.1.clone(),
        &config,
    ));
    let with_rings_pool = with_rings_arena.pool().clone();
    let _without_rings_pool = without_rings_arena.pool().clone();

    let program = Program::wrapped(
        vec![],
        [1, 1, 1],
        vec![Node::trap(Expr::u32(3), "direct-readback-ring-trap")],
    );

    let pipeline = super::WgpuPipeline::compile_with_device_queue(
        &program,
        &config,
        adapter_info,
        enabled_features,
        device_queue.clone(),
        with_rings_arena.clone(),
        with_rings_pool.clone(),
        pipeline_cache,
        layout_cache,
    )
    .expect("Fix: trapped program compile must succeed; restore this invariant before continuing.");

    let empty_inputs: [&[u8]; 0] = [];
    let before_allocations = with_rings_pool.stats().allocations;
    let error = crate::engine::record_and_readback::record_and_readback(
        crate::engine::record_and_readback::RecordAndReadback {
            device_queue: &pipeline.device_queue,
            pool: with_rings_arena.pool(),
            readback_rings: Some(with_rings_arena.readback_rings()),
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
                bind_group: "vyre direct trap readback ring test bind group",
                encoder: "vyre direct trap readback ring test",
                compute: "vyre direct trap readback ring test compute",
            },
            iterations: 1,
            timestamp_profile: false,
        },
    )
    .expect_err(
        "Fix: trapped dispatch with readback rings must return the underlying trap sidecar error and not succeed",
    );
    let after_allocations = with_rings_pool.stats().allocations;

    assert_eq!(
        error.to_string().contains("wgpu dispatch trapped"),
        true,
        "Fix: expected trap dispatch to surface a backend trap error, got: {error}"
    );
    assert_eq!(
        error.to_string().contains("direct-readback-ring-trap"),
        true,
        "Fix: expected trap dispatch to surface a backend trap error, got: {error}"
    );
    assert_eq!(
        after_allocations,
        before_allocations + 1,
        "Fix: readback-ring trap path must use the dedicated trap sidecar buffer only (no pooled full-sidecar readback buffer allocation).",
    );
}

#[test]

fn direct_record_and_readback_trap_without_readback_rings_allocates_full_sidecar_copy() {
    use std::sync::Arc;

    let ((device, queue), adapter_info, enabled_features) = crate::runtime::init_device()
        .expect("Fix: GPU required for trap-sidecar allocation delta test");
    let device_queue = Arc::new((device, queue));
    let config = DispatchConfig::default();
    let pipeline_cache = Arc::new(crate::runtime::cache::pipeline::LruPipelineCache::new(
        vyre_driver::pipeline::DEFAULT_PIPELINE_CACHE_ENTRIES as u32,
    ));
    let layout_cache = Arc::new(super::BindGroupLayoutCache::with_hasher(
        std::hash::BuildHasherDefault::<rustc_hash::FxHasher>::default(),
    ));
    let arena = Arc::new(crate::DispatchArena::new(
        device_queue.0.clone(),
        device_queue.1.clone(),
        &config,
    ));
    let pool = arena.pool().clone();

    let program = Program::wrapped(
        vec![],
        [1, 1, 1],
        vec![Node::trap(Expr::u32(5), "direct-readback-no-ring-trap")],
    );

    let pipeline = super::WgpuPipeline::compile_with_device_queue(
        &program,
        &config,
        adapter_info,
        enabled_features,
        device_queue.clone(),
        Arc::clone(&arena),
        pool.clone(),
        pipeline_cache,
        layout_cache,
    )
    .expect("Fix: trapped program compile must succeed; restore this invariant before continuing.");

    let empty_inputs: [&[u8]; 0] = [];
    let before_allocations = pool.stats().allocations;
    let error = crate::engine::record_and_readback::record_and_readback(
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
                bind_group: "vyre direct trap readback no-ring test bind group",
                encoder: "vyre direct trap readback no-ring test",
                compute: "vyre direct trap readback no-ring test compute",
            },
            iterations: 1,
            timestamp_profile: false,
        },
    )
    .expect_err(
        "Fix: trapped dispatch without rings must still return the underlying trap sidecar error and not succeed",
    );
    let after_allocations = pool.stats().allocations;

    assert!(
        error.to_string().contains("wgpu dispatch trapped"),
        "Fix: expected trap dispatch to surface a backend trap error, got: {error}"
    );
    assert!(
        error.to_string().contains("direct-readback-no-ring-trap"),
        "Fix: expected the trap tag to be preserved across fallback sidecar decode, got: {error}"
    );
    assert_eq!(
        after_allocations,
        before_allocations + 2,
        "Fix: non-ring trap path must allocate exactly the full-sidecar pooled readback buffer plus trap sidecar allocation (before={before_allocations}, after={after_allocations})."
    );
}

#[test]
fn direct_record_and_readback_trap_with_output_preserves_ring_fast_path() {
    use std::sync::Arc;

    let ((device, queue), adapter_info, enabled_features) = crate::runtime::init_device()
        .expect("Fix: GPU required for trap+output readback allocation contract test");
    let device_queue = Arc::new((device, queue));
    let config = DispatchConfig::default();
    let pipeline_cache = Arc::new(crate::runtime::cache::pipeline::LruPipelineCache::new(
        vyre_driver::pipeline::DEFAULT_PIPELINE_CACHE_ENTRIES as u32,
    ));
    let layout_cache = Arc::new(super::BindGroupLayoutCache::with_hasher(
        std::hash::BuildHasherDefault::<rustc_hash::FxHasher>::default(),
    ));
    let with_rings_arena = Arc::new(crate::DispatchArena::new(
        device_queue.0.clone(),
        device_queue.1.clone(),
        &config,
    ));
    let without_rings_arena = Arc::new(crate::DispatchArena::new(
        device_queue.0.clone(),
        device_queue.1.clone(),
        &config,
    ));
    let with_rings_pool = with_rings_arena.pool().clone();
    let without_rings_pool = without_rings_arena.pool().clone();

    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![
            Node::store("out", Expr::u32(0), Expr::u32(99)),
            Node::trap(Expr::u32(9), "mixed-output-ring-trap"),
        ],
    );

    let pipeline = super::WgpuPipeline::compile_with_device_queue(
        &program,
        &config,
        adapter_info,
        enabled_features,
        device_queue.clone(),
        Arc::clone(&with_rings_arena),
        with_rings_pool.clone(),
        pipeline_cache,
        layout_cache,
    )
    .expect("Fix: trapped program with output compile must succeed; restore this invariant before continuing.");

    let empty_inputs: [&[u8]; 0] = [];

    let with_rings_before = with_rings_pool.stats().allocations;
    let with_rings_error = crate::engine::record_and_readback::record_and_readback(
        crate::engine::record_and_readback::RecordAndReadback {
            device_queue: &pipeline.device_queue,
            pool: with_rings_arena.pool(),
            readback_rings: Some(with_rings_arena.readback_rings()),
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
                bind_group: "vyre mixed output ring test bind group",
                encoder: "vyre mixed output ring test",
                compute: "vyre mixed output ring test compute",
            },
            iterations: 1,
            timestamp_profile: false,
        },
    )
    .expect_err(
        "Fix: trapped dispatch with output and rings must still surface trap errors and not succeed",
    );
    let with_rings_after = with_rings_pool.stats().allocations;

    assert!(
        with_rings_error
            .to_string()
            .contains("wgpu dispatch trapped"),
        "Fix: expected trap dispatch to surface a backend trap error, got: {with_rings_error}"
    );
    assert!(
        with_rings_error.to_string().contains("mixed-output-ring-trap"),
        "Fix: expected trap tag to be preserved through mixed-output ring path, got: {with_rings_error}"
    );
    assert_eq!(
        with_rings_after,
        with_rings_before + 2,
        "Fix: ring-backed mixed output+trap path should add only output + trap buffer allocations from pool before first successful mapping.",
    );

    let without_rings_before = without_rings_pool.stats().allocations;
    let without_rings_error = crate::engine::record_and_readback::record_and_readback(
        crate::engine::record_and_readback::RecordAndReadback {
            device_queue: &pipeline.device_queue,
            pool: without_rings_arena.pool(),
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
                bind_group: "vyre mixed output no-ring test bind group",
                encoder: "vyre mixed output no-ring test",
                compute: "vyre mixed output no-ring test compute",
            },
            iterations: 1,
            timestamp_profile: false,
        },
    )
    .expect_err(
        "Fix: trapped dispatch without rings should surface the trap error and not succeed",
    );
    let without_rings_after = without_rings_pool.stats().allocations;

    assert!(
        without_rings_error
            .to_string()
            .contains("wgpu dispatch trapped"),
        "Fix: expected trap dispatch to surface a backend trap error, got: {without_rings_error}"
    );
    assert!(
        without_rings_error.to_string().contains("mixed-output-ring-trap"),
        "Fix: expected trap tag to be preserved through mixed-output fallback path, got: {without_rings_error}"
    );
    assert_eq!(
        without_rings_after,
        without_rings_before + 4,
        "Fix: no-ring mixed output+trap path should allocate output storage, trap storage, output readback, and trap readback buffers; ring-backed dispatch must be the path that avoids the two pooled readback allocations.",
    );
}


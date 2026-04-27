use super::{enforce_actual_output_budget, hex_short, output_layouts_from_program, DispatchConfig};
use std::fmt::Write as _;
use vyre_foundation::execution_plan::{self, ReadbackStrategy};
use vyre_foundation::ir::{BufferDecl, DataType, Expr, Node, Program};

#[test]
fn hex_short_truncates_to_eight_bytes() {
    let hash = *blake3::hash(b"vyre-pipeline").as_bytes();
    let expected = hash[..8]
        .iter()
        .fold(String::with_capacity(16), |mut out, byte| {
            write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
            out
        });
    assert_eq!(hex_short(&hash).len(), 16);
    assert_eq!(hex_short(&hash), expected);
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
    let plan = execution_plan::plan(&program).expect("trimmed output program must plan");
    assert_eq!(
        plan.strategy.readback,
        ReadbackStrategy::Trimmed {
            visible_bytes: 8,
            avoided_bytes: 4088,
        }
    );
    let layouts = output_layouts_from_program(&program).expect("layout must derive");
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
        super::MAX_PIPELINE_CACHE_ENTRIES as u32,
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
        crate::DispatchArena::new(),
        pool.clone(),
        pipeline_cache.clone(),
    )
    .expect("first compile must succeed");

    let p2 = super::WgpuPipeline::compile_with_device_queue(
        &program1,
        &config,
        adapter_info.clone(),
        enabled_features,
        device_queue.clone(),
        crate::DispatchArena::new(),
        pool.clone(),
        pipeline_cache.clone(),
    )
    .expect("second compile of same program must succeed");

    assert!(
        Arc::ptr_eq(&p1.bind_group_cache, &p2.bind_group_cache),
        "Fix: same compiled shader must share BindGroupCache (HOT-01)"
    );

    let (input_handles, mut output_handles) = p1
        .legacy_handles_from_inputs(&[])
        .expect("legacy handle creation must succeed");
    p1.dispatch_persistent(&input_handles, &mut output_handles, None, [1, 1, 1])
        .expect("first dispatch must succeed");
    let stats_after_miss = p1.bind_group_cache_stats();
    assert_eq!(
        stats_after_miss.misses, 1,
        "Fix: first dispatch of a new signature must be a cache miss"
    );
    assert_eq!(stats_after_miss.hits, 0);

    p1.dispatch_persistent(&input_handles, &mut output_handles, None, [1, 1, 1])
        .expect("second dispatch must succeed");
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
        crate::DispatchArena::new(),
        pool,
        pipeline_cache,
    )
    .expect("compile of different program must succeed");

    assert!(
        !Arc::ptr_eq(&p1.bind_group_cache, &p3.bind_group_cache),
        "Fix: different compiled shaders must have independent BindGroupCaches"
    );
}

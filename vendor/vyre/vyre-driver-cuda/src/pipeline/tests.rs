use std::sync::Arc;

use smallvec::smallvec;
use vyre_driver::binding::{Binding, BindingPlan, BindingRole};
use vyre_driver::replace_output_buffers_preserving_slots;
use vyre_driver::LaunchPlan;

use crate::backend::CudaDispatchPlan;
use crate::device::CudaDeviceCaps;

use super::{add_shape_bytes, cuda_graph_lane_count_for_batch};

fn blackwell_caps(total_memory: u64) -> CudaDeviceCaps {
    CudaDeviceCaps {
        name: "NVIDIA GeForce RTX 5090".to_string(),
        ordinal: 0,
        compute_capability: (12, 0),
        total_memory,
        max_threads_per_block: 1024,
        max_block_dim: [1024, 1024, 64],
        max_grid_dim: [2_147_483_647, 65_535, 65_535],
        shared_memory_per_block: 128 * 1024,
        shared_memory_per_sm: 256 * 1024,
        warp_size: 32,
        cooperative_launch: true,
        concurrent_kernels: true,
        async_engine_count: 2,
        multi_processor_count: 170,
        l2_cache_bytes: 96 * 1024 * 1024,
        memory_clock_rate_khz: 14_000_000,
        global_memory_bus_width_bits: 512,
        max_registers_per_block: 65_536,
        max_registers_per_sm: 65_536,
        max_threads_per_sm: 2048,
    }
}

fn single_input_output_plan(byte_len: usize) -> CudaDispatchPlan {
    CudaDispatchPlan {
        bindings: BindingPlan {
            bindings: vec![Binding {
                name: Arc::from("state"),
                binding: 0,
                buffer_index: 0,
                role: BindingRole::InputOutput,
                element_size: 1,
                preferred_alignment: 1,
                element_count: byte_len as u32,
                static_byte_len: Some(byte_len),
                input_index: Some(0),
                output_index: Some(0),
            }],
            input_indices: vec![0],
            output_indices: vec![0],
            shared_indices: vec![],
        },
        output_binding_indices: smallvec![0],
        launch: LaunchPlan {
            grid: [1, 1, 1],
            workgroup: [128, 1, 1],
            element_count: byte_len as u32,
            param_words: vec![1, 2, 3, 4],
            max_binding_alignment: 1,
        },
        cooperative: false,
        fixpoint_iterations: 1,
    }
}

#[test]
fn cuda_pipeline_dynamic_dispatch_reuses_existing_output_slots() {
    let mut outputs = vec![Vec::with_capacity(8), Vec::with_capacity(4)];
    let outputs_addr = outputs.as_ptr() as usize;
    let first_slot_addr = outputs[0].as_ptr() as usize;
    let second_slot_addr = outputs[1].as_ptr() as usize;

    replace_output_buffers_preserving_slots(vec![vec![1, 2, 3], vec![4]], &mut outputs);

    assert_eq!(outputs, vec![vec![1, 2, 3], vec![4]]);
    assert_eq!(outputs.as_ptr() as usize, outputs_addr);
    assert_eq!(outputs[0].as_ptr() as usize, first_slot_addr);
    assert_eq!(outputs[1].as_ptr() as usize, second_slot_addr);
}

#[test]
fn cuda_graph_lane_planner_scales_past_legacy_four_lane_cap() {
    let caps = blackwell_caps(32 * 1024 * 1024 * 1024);
    let plan = single_input_output_plan(1024);
    let input = vec![7_u8; 1024];
    let row = [input.as_slice()];
    let batches: Vec<&[&[u8]]> = vec![row.as_slice(); 64];

    let lanes = cuda_graph_lane_count_for_batch(&caps, &plan, &batches)
        .expect("graph replay lane planning should fit");

    assert!(lanes > 4);
    assert_eq!(lanes, 22);
}

#[test]
fn cuda_graph_lane_planner_caps_large_graphs_by_vram_budget() {
    let caps = blackwell_caps(512 * 1024 * 1024);
    let plan = single_input_output_plan(64 * 1024 * 1024);
    let input = vec![1_u8; 64 * 1024 * 1024];
    let row = [input.as_slice()];
    let batches: Vec<&[&[u8]]> = vec![row.as_slice(); 64];

    let lanes = cuda_graph_lane_count_for_batch(&caps, &plan, &batches)
        .expect("graph replay lane planning should fit");

    assert_eq!(lanes, 1);
}

#[test]
fn cuda_graph_replay_is_release_default_not_opt_in_debug_path() {
    let source = include_str!("../pipeline.rs");

    assert!(
        source.contains("VYRE_CUDA_GRAPH_REPLAY")
            && source.contains("Ok(\"0\" | \"false\" | \"FALSE\" | \"off\" | \"OFF\")"),
        "Fix: CUDA graph replay must be enabled by default with only an explicit debug disable."
    );
    assert!(
        !source.contains("var_os(\"VYRE_CUDA_GRAPH_REPLAY\").is_some()"),
        "Fix: CUDA graph replay must not be opt-in on the release path."
    );
}

#[test]
fn static_launch_param_upload_sync_is_telemetry_visible() {
    let source = include_str!("static_params.rs");
    assert!(
        source.contains("backend.telemetry.record_sync_point();"),
        "Fix: CUDA compiled-pipeline static parameter upload must record its stream synchronization in telemetry."
    );
}

#[test]
fn cuda_graph_shape_bytes_overflow_fails_loudly_without_saturating_arithmetic() {
    assert_eq!(add_shape_bytes(usize::MAX - 1, 1).unwrap(), usize::MAX);
    let overflow = add_shape_bytes(usize::MAX - 1, 2);
    assert!(
        matches!(overflow, Err(vyre_driver::BackendError::InvalidProgram { .. })),
        "Fix: CUDA graph replay shape byte overflow must return a typed error instead of capping or panicking."
    );

    let source = include_str!("../pipeline.rs");
    assert!(
        !source.contains(concat!(".saturating_add", "(CUDA_GRAPH_REPLAY_SMS_PER_LANE"))
            && !source.contains(concat!("bytes = bytes", ".saturating_add")),
        "Fix: CUDA graph lane planning must use exact arithmetic with an explicit overflow cap, not generic saturating arithmetic."
    );
    assert!(
        !source.contains("unwrap_or(usize::MAX)"),
        "Fix: CUDA graph replay shape byte overflow must not silently cap to usize::MAX."
    );
}

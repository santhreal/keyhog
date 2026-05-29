//! Metric-key plumbing: small key/value helpers used by `collect.rs` and
//! `report.rs` to look up metrics by stable name.

pub(super) fn rate_per_second_x1000(units: u64, wall_ns: u64, scale: u64) -> u64 {
    let numerator = u128::from(units) * 1_000_000_000_000u128;
    let denominator = u128::from(wall_ns) * u128::from(scale);
    (numerator / denominator).min(u128::from(u64::MAX)) as u64
}

pub(super) fn custom_metric_value(
    metrics: &crate::api::metric::BenchMetrics,
    name: &str,
) -> Option<u64> {
    metrics
        .custom
        .iter()
        .find(|point| point.name == name)
        .map(|point| point.value)
}

pub(super) fn gpu_counter_value(
    metrics: &crate::api::metric::BenchMetrics,
    name: &str,
) -> Option<u64> {
    metrics
        .gpu_counter
        .iter()
        .find(|counter| counter.name == name)
        .map(|counter| counter.value)
}

pub(super) fn custom_metric_key(prefix: &'static str, name: &str) -> Option<&'static str> {
    match (prefix, name) {
        ("", "flop_count") => Some("flop_count"),
        ("", "clock_mem_max_mhz") => Some("clock_mem_max_mhz"),
        ("", "clock_mem_current_mhz") => Some("clock_mem_current_mhz"),
        ("", "clock_graphics_max_mhz") => Some("clock_graphics_max_mhz"),
        ("", "clock_graphics_current_mhz") => Some("clock_graphics_current_mhz"),
        ("", "pstate") => Some("pstate"),
        ("", "clock_throttle_reasons_active") => Some("clock_throttle_reasons_active"),
        ("", "power_draw_w") => Some("power_draw_w"),
        ("", "power_limit_w") => Some("power_limit_w"),
        ("", "temperature_c") => Some("temperature_c"),
        ("", "memory_total_mib") => Some("memory_total_mib"),
        ("", "memory_used_mib") => Some("memory_used_mib"),
        ("", "memory_free_mib") => Some("memory_free_mib"),
        ("", "utilization_gpu_pct") => Some("utilization_gpu_pct"),
        ("", "utilization_mem_pct") => Some("utilization_mem_pct"),
        ("", "memory_peak_gb_s_x1000") => Some("memory_peak_gb_s_x1000"),
        ("", "thermal_unstable") => Some("thermal_unstable"),
        ("", "megakernel_slots") => Some("megakernel_slots"),
        ("", "megakernel_dispatch_latency_ns") => Some("megakernel_dispatch_latency_ns"),
        ("", "megakernel_slots_per_sec_x1000") => Some("megakernel_slots_per_sec_x1000"),
        ("", "megakernel_roundtrip_buffers") => Some("megakernel_roundtrip_buffers"),
        ("", "megakernel_speculation_samples") => Some("megakernel_speculation_samples"),
        ("", "megakernel_speculation_adopted") => Some("megakernel_speculation_adopted"),
        ("", "megakernel_speculation_rejected") => Some("megakernel_speculation_rejected"),
        ("", "megakernel_speculation_side_compile_cost_ns") => {
            Some("megakernel_speculation_side_compile_cost_ns")
        }
        ("", "megakernel_speculation_autotune_records") => {
            Some("megakernel_speculation_autotune_records")
        }
        ("", "megakernel_queue_plan_ns") => Some("megakernel_queue_plan_ns"),
        ("", "megakernel_queue_publish_ns") => Some("megakernel_queue_publish_ns"),
        ("", "megakernel_backend_dispatch_ns") => Some("megakernel_backend_dispatch_ns"),
        ("", "megakernel_lineage_ns") => Some("megakernel_lineage_ns"),
        ("", "megakernel_published_items") => Some("megakernel_published_items"),
        ("", "megakernel_lineage_items") => Some("megakernel_lineage_items"),
        ("", "megakernel_deduped_items") => Some("megakernel_deduped_items"),
        ("", "megakernel_items_processed") => Some("megakernel_items_processed"),
        ("", "megakernel_items_remaining") => Some("megakernel_items_remaining"),
        ("", "megakernel_bytes_uploaded") => Some("megakernel_bytes_uploaded"),
        ("", "megakernel_bytes_read_back") => Some("megakernel_bytes_read_back"),
        ("", "megakernel_bytes_moved") => Some("megakernel_bytes_moved"),
        ("", "megakernel_resident_allocations") => Some("megakernel_resident_allocations"),
        ("", "megakernel_kernel_launches") => Some("megakernel_kernel_launches"),
        ("", "megakernel_sync_points") => Some("megakernel_sync_points"),
        ("", "megakernel_occupancy_proxy_bps") => Some("megakernel_occupancy_proxy_bps"),
        ("", "megakernel_frontier_density_bps") => Some("megakernel_frontier_density_bps"),
        ("", "megakernel_readback_buffers") => Some("megakernel_readback_buffers"),
        ("", "megakernel_compiled_pipeline_cache_hit") => {
            Some("megakernel_compiled_pipeline_cache_hit")
        }
        ("", "megakernel_resident_input_cache_hit") => Some("megakernel_resident_input_cache_hit"),
        ("", "megakernel_topology") => Some("megakernel_topology"),
        ("", "megakernel_pressure") => Some("megakernel_pressure"),
        ("", "megakernel_execution_mode") => Some("megakernel_execution_mode"),
        ("", "megakernel_hit_capacity") => Some("megakernel_hit_capacity"),
        ("", "megakernel_estimated_peak_device_bytes") => {
            Some("megakernel_estimated_peak_device_bytes")
        }
        ("", "megakernel_device_memory_budget_bytes") => {
            Some("megakernel_device_memory_budget_bytes")
        }
        ("", "megakernel_condition_slots") => Some("megakernel_condition_slots"),
        ("", "megakernel_condition_fired") => Some("megakernel_condition_fired"),
        ("", "megakernel_condition_slots_per_sec_x1000") => {
            Some("megakernel_condition_slots_per_sec_x1000")
        }
        ("", "dataflow_nodes") => Some("dataflow_nodes"),
        ("", "dataflow_bitset_words") => Some("dataflow_bitset_words"),
        ("", "dataflow_graph_nodes") => Some("dataflow_graph_nodes"),
        ("", "dataflow_graph_edges") => Some("dataflow_graph_edges"),
        ("", "dataflow_ifds_step") => Some("dataflow_ifds_step"),
        ("", "dataflow_points_to_alias_step") => Some("dataflow_points_to_alias_step"),
        ("", "sparse_items") => Some("sparse_items"),
        ("", "callgraph_nodes") => Some("callgraph_nodes"),
        ("", "metadata_records") => Some("metadata_records"),
        ("", "lower_ops_before") => Some("lower_ops_before"),
        ("", "lower_ops_after") => Some("lower_ops_after"),
        ("", "lower_ops_eliminated") => Some("lower_ops_eliminated"),
        ("", "lower_bindings_dropped") => Some("lower_bindings_dropped"),
        ("", "lower_off_graph_dropped") => Some("lower_off_graph_dropped"),
        ("", "lower_baseline_issue_score") => Some("lower_baseline_issue_score"),
        ("", "lower_optimized_issue_score") => Some("lower_optimized_issue_score"),
        ("", "lower_coalesce_problematic_before") => Some("lower_coalesce_problematic_before"),
        ("", "lower_coalesce_problematic_after") => Some("lower_coalesce_problematic_after"),
        ("", "lower_shared_candidates_before") => Some("lower_shared_candidates_before"),
        ("", "lower_shared_candidates_after") => Some("lower_shared_candidates_after"),
        ("", "lower_bank_critical_before") => Some("lower_bank_critical_before"),
        ("", "lower_bank_critical_after") => Some("lower_bank_critical_after"),
        ("", "lower_vec_pack_chains_before") => Some("lower_vec_pack_chains_before"),
        ("", "lower_vec_pack_chains_after") => Some("lower_vec_pack_chains_after"),
        ("", "lower_vec_pack_ops_eliminable_before") => {
            Some("lower_vec_pack_ops_eliminable_before")
        }
        ("", "lower_vec_pack_ops_eliminable_after") => Some("lower_vec_pack_ops_eliminable_after"),
        ("", "lower_layout_candidates_before") => Some("lower_layout_candidates_before"),
        ("", "lower_layout_candidates_after") => Some("lower_layout_candidates_after"),
        ("", "lower_converged") => Some("lower_converged"),
        ("", "optimizer_input_nodes") => Some("optimizer_input_nodes"),
        ("", "optimizer_output_nodes") => Some("optimizer_output_nodes"),
        ("", "optimizer_nodes_eliminated") => Some("optimizer_nodes_eliminated"),
        ("", "alias_pass_wins") => Some("alias_pass_wins"),
        ("", "alias_fact_count") => Some("alias_fact_count"),
        ("", "alias_cross_binding_fact_count") => Some("alias_cross_binding_fact_count"),
        ("", "reaching_def_fact_count") => Some("reaching_def_fact_count"),
        ("", "alias_total_ops_after") => Some("alias_total_ops_after"),
        ("", "conservative_total_ops_after") => Some("conservative_total_ops_after"),
        ("", "alias_dse_store_count") => Some("alias_dse_store_count"),
        ("", "conservative_dse_store_count") => Some("conservative_dse_store_count"),
        ("", "alias_stlf_final_value_id") => Some("alias_stlf_final_value_id"),
        ("", "conservative_stlf_final_value_id") => Some("conservative_stlf_final_value_id"),
        ("", "alias_licm_loop_loads") => Some("alias_licm_loop_loads"),
        ("", "conservative_licm_loop_loads") => Some("conservative_licm_loop_loads"),
        ("", "alias_fusion_loop_count") => Some("alias_fusion_loop_count"),
        ("", "conservative_fusion_loop_count") => Some("conservative_fusion_loop_count"),
        ("", "alias_fission_loop_count") => Some("alias_fission_loop_count"),
        ("", "conservative_fission_loop_count") => Some("conservative_fission_loop_count"),
        ("", "benchmark_repeats") => Some("benchmark_repeats"),
        ("", "ptx_corpus_kernels") => Some("ptx_corpus_kernels"),
        ("", "ptx_predication_candidates") => Some("ptx_predication_candidates"),
        ("", "ptx_safe_predication_candidates") => Some("ptx_safe_predication_candidates"),
        ("", "ptx_vec_load_candidates") => Some("ptx_vec_load_candidates"),
        ("", "ptx_vec_store_candidates") => Some("ptx_vec_store_candidates"),
        ("", "ptx_async_copy_candidates") => Some("ptx_async_copy_candidates"),
        ("", "ptx_tensor_core_candidates") => Some("ptx_tensor_core_candidates"),
        ("", "ptx_ldmatrix_capable_targets") => Some("ptx_ldmatrix_capable_targets"),
        ("", "ptx_scheduled_fillers") => Some("ptx_scheduled_fillers"),
        ("", "ptx_predicated_stores") => Some("ptx_predicated_stores"),
        ("", "ptx_branch_labels") => Some("ptx_branch_labels"),
        ("", "ptx_cp_async_emitted") => Some("ptx_cp_async_emitted"),
        ("", "ptx_mma_sync_emitted") => Some("ptx_mma_sync_emitted"),
        ("", "ptx_vectorized_loads_emitted") => Some("ptx_vectorized_loads_emitted"),
        ("", "ptx_vectorized_stores_emitted") => Some("ptx_vectorized_stores_emitted"),
        ("", "ptx_vector_kernel_scalar_loads") => Some("ptx_vector_kernel_scalar_loads"),
        ("", "ptx_vector_kernel_scalar_stores") => Some("ptx_vector_kernel_scalar_stores"),
        ("", "ptx_vector_kernel_scalar_index_adds") => Some("ptx_vector_kernel_scalar_index_adds"),
        ("", "ptx_bytes_emitted") => Some("ptx_bytes_emitted"),
        ("", "egraph_case_count") => Some("egraph_case_count"),
        ("", "egraph_bitwise_case_count") => Some("egraph_bitwise_case_count"),
        ("", "egraph_boolean_case_count") => Some("egraph_boolean_case_count"),
        ("", "egraph_input_ops") => Some("egraph_input_ops"),
        ("", "egraph_output_ops") => Some("egraph_output_ops"),
        ("", "egraph_baseline_ops_after") => Some("egraph_baseline_ops_after"),
        ("", "egraph_iterations") => Some("egraph_iterations"),
        ("", "egraph_equality_classes") => Some("egraph_equality_classes"),
        ("", "egraph_applied_rewrites") => Some("egraph_applied_rewrites"),
        ("", "egraph_hit_iteration_limit") => Some("egraph_hit_iteration_limit"),
        ("", "egraph_hit_node_limit") => Some("egraph_hit_node_limit"),
        ("baseline_", "flop_count") => Some("baseline_flop_count"),
        ("baseline_", "megakernel_items_processed") => Some("baseline_megakernel_items_processed"),
        _ => None,
    }
}

pub(super) fn derived_metric_key(prefix: &'static str, name: &str) -> Option<&'static str> {
    match (prefix, name) {
        ("", "wall_gb_s_x1000") => Some("wall_gb_s_x1000"),
        ("", "device_gb_s_x1000") => Some("device_gb_s_x1000"),
        ("", "gflops_x1000") => Some("gflops_x1000"),
        ("", "roofline_mem_pct_x1000") => Some("roofline_mem_pct_x1000"),
        ("baseline_", "wall_gb_s_x1000") => Some("baseline_wall_gb_s_x1000"),
        ("baseline_", "device_gb_s_x1000") => Some("baseline_device_gb_s_x1000"),
        ("baseline_", "gflops_x1000") => Some("baseline_gflops_x1000"),
        ("baseline_", "roofline_mem_pct_x1000") => Some("baseline_roofline_mem_pct_x1000"),
        _ => None,
    }
}

pub(super) fn metric_key(prefix: &'static str, name: &'static str) -> Option<&'static str> {
    match (prefix, name) {
        ("", "wall_ns") => Some("wall_ns"),
        ("", "cpu_ns") => Some("cpu_ns"),
        ("", "compile_ns") => Some("compile_ns"),
        ("", "validate_ns") => Some("validate_ns"),
        ("", "optimize_ns") => Some("optimize_ns"),
        ("", "lower_ns") => Some("lower_ns"),
        ("", "cache_lookup_ns") => Some("cache_lookup_ns"),
        ("", "cache_hit") => Some("cache_hit"),
        ("", "upload_ns") => Some("upload_ns"),
        ("", "dispatch_ns") => Some("dispatch_ns"),
        ("", "kernel_queue_submit_ns") => Some("kernel_queue_submit_ns"),
        ("", "kernel_execute_ns") => Some("kernel_execute_ns"),
        ("", "device_sync_ns") => Some("device_sync_ns"),
        ("", "readback_ns") => Some("readback_ns"),
        ("", "verify_ns") => Some("verify_ns"),
        ("", "alloc_count") => Some("alloc_count"),
        ("", "alloc_bytes") => Some("alloc_bytes"),
        ("", "peak_rss_bytes") => Some("peak_rss_bytes"),
        ("", "input_bytes") => Some("input_bytes"),
        ("", "output_bytes") => Some("output_bytes"),
        ("", "bytes_touched") => Some("bytes_touched"),
        ("", "bytes_read") => Some("bytes_read"),
        ("", "bytes_written") => Some("bytes_written"),
        ("", "atomic_op_count") => Some("atomic_op_count"),
        ("", "wire_bytes") => Some("wire_bytes"),
        ("baseline_", "wall_ns") => Some("baseline_wall_ns"),
        ("baseline_", "cpu_ns") => Some("baseline_cpu_ns"),
        ("baseline_", "compile_ns") => Some("baseline_compile_ns"),
        ("baseline_", "validate_ns") => Some("baseline_validate_ns"),
        ("baseline_", "optimize_ns") => Some("baseline_optimize_ns"),
        ("baseline_", "lower_ns") => Some("baseline_lower_ns"),
        ("baseline_", "cache_lookup_ns") => Some("baseline_cache_lookup_ns"),
        ("baseline_", "cache_hit") => Some("baseline_cache_hit"),
        ("baseline_", "upload_ns") => Some("baseline_upload_ns"),
        ("baseline_", "dispatch_ns") => Some("baseline_dispatch_ns"),
        ("baseline_", "kernel_queue_submit_ns") => Some("baseline_kernel_queue_submit_ns"),
        ("baseline_", "kernel_execute_ns") => Some("baseline_kernel_execute_ns"),
        ("baseline_", "device_sync_ns") => Some("baseline_device_sync_ns"),
        ("baseline_", "readback_ns") => Some("baseline_readback_ns"),
        ("baseline_", "verify_ns") => Some("baseline_verify_ns"),
        ("baseline_", "alloc_count") => Some("baseline_alloc_count"),
        ("baseline_", "alloc_bytes") => Some("baseline_alloc_bytes"),
        ("baseline_", "peak_rss_bytes") => Some("baseline_peak_rss_bytes"),
        ("baseline_", "input_bytes") => Some("baseline_input_bytes"),
        ("baseline_", "output_bytes") => Some("baseline_output_bytes"),
        ("baseline_", "bytes_touched") => Some("baseline_bytes_touched"),
        ("baseline_", "bytes_read") => Some("baseline_bytes_read"),
        ("baseline_", "bytes_written") => Some("baseline_bytes_written"),
        ("baseline_", "atomic_op_count") => Some("baseline_atomic_op_count"),
        ("baseline_", "wire_bytes") => Some("baseline_wire_bytes"),
        _ => None,
    }
}

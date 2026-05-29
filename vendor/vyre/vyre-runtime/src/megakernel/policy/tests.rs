use super::cache::{LaunchRecommendationCache, LaunchRecommendationCacheKey};
use super::*;

#[test]
fn policy_recommends_padded_geometry_and_hit_capacity() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 300,
            requested_worker_groups: 64,
            max_workgroup_size_x: 256,
            requested_hit_capacity: 0,
            expected_hits_per_item: 3,
            ..MegakernelLaunchRequest::direct(300, 64, 256)
        })
        .expect("Fix: policy should accept non-zero adapter limits");
    assert_eq!(rec.geometry.workgroup_size_x, 64);
    assert_eq!(rec.geometry.slot_count, 320);
    assert_eq!(rec.geometry.dispatch_grid, [5, 1, 1]);
    assert_eq!(rec.hit_capacity, 1800);
    assert_eq!(rec.estimated_peak_device_bytes, 28_800);
    assert_eq!(rec.device_memory_budget_bytes, 0);
    assert_eq!(rec.topology, MegakernelDispatchTopology::SparseFrontier);
}

#[test]
fn telemetry_pressure_selects_jit_and_priority_aging() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 8192,
            requested_worker_groups: 64,
            max_workgroup_size_x: 256,
            hot_opcode_count: 8,
            requeue_count: 1,
            max_priority_age: 64,
            ..MegakernelLaunchRequest::direct(8192, 64, 256)
        })
        .expect("Fix: policy should accept non-zero adapter limits");
    assert_eq!(rec.pressure, MegakernelQueuePressure::Saturated);
    assert_eq!(rec.execution_mode, MegakernelExecutionMode::Jit);
    assert_eq!(rec.topology, MegakernelDispatchTopology::SparseFrontier);
    assert!(rec.promote_hot_opcodes);
    assert!(rec.age_priority_work);
}

#[test]
fn dense_large_hot_graph_selects_fused_dense_topology() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 131_072,
            requested_worker_groups: 256,
            max_workgroup_size_x: 256,
            graph_node_count: 32_768,
            graph_edge_count: 500_000,
            frontier_density_bps: 7_500,
            hot_window_count: policy.hot_window_threshold,
            ..MegakernelLaunchRequest::direct(131_072, 256, 256)
        })
        .expect("Fix: fused dense topology should accept valid adapter limits");

    assert_eq!(rec.topology, MegakernelDispatchTopology::FusedDense);
    assert_eq!(rec.execution_mode, MegakernelExecutionMode::Jit);
}

#[test]
fn high_memory_pressure_overrides_dense_frontier() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 16_384,
            requested_worker_groups: 128,
            max_workgroup_size_x: 256,
            graph_node_count: 16_384,
            graph_edge_count: 250_000,
            frontier_density_bps: 9_000,
            memory_pressure_bps: policy.memory_pressure_threshold_bps,
            ..MegakernelLaunchRequest::direct(16_384, 128, 256)
        })
        .expect("Fix: memory-constrained topology should accept valid adapter limits");

    assert_eq!(rec.topology, MegakernelDispatchTopology::MemoryConstrained);
    assert!(
        rec.worker_groups < 128,
        "memory-constrained topology must lower worker-group pressure, got {}",
        rec.worker_groups
    );
    assert_eq!(
        rec.hit_capacity, 16_384,
        "memory-constrained topology must avoid the normal sparse-hit over-allocation multiplier"
    );
}

#[test]
fn explicit_hit_capacity_survives_memory_constrained_worker_shedding() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 16_384,
            requested_worker_groups: 128,
            max_workgroup_size_x: 256,
            requested_hit_capacity: 65_536,
            memory_pressure_bps: 10_000,
            ..MegakernelLaunchRequest::direct(16_384, 128, 256)
        })
        .expect(
            "Fix: memory-constrained explicit-capacity launch should accept valid adapter limits",
        );

    assert_eq!(rec.topology, MegakernelDispatchTopology::MemoryConstrained);
    assert_eq!(rec.hit_capacity, 65_536);
    assert_eq!(rec.worker_groups, 64);
}

#[test]
fn device_memory_budget_rejects_oversized_hit_plan_before_allocation() {
    let policy = MegakernelLaunchPolicy::standard();
    let err = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 1024,
            requested_worker_groups: 64,
            max_workgroup_size_x: 256,
            expected_hits_per_item: 4,
            resident_device_bytes: 1024,
            device_memory_budget_bytes: 64 * 1024,
            ..MegakernelLaunchRequest::direct(1024, 64, 256)
        })
        .expect_err("Fix: launch policy must reject plans that exceed explicit device budget");

    match err {
        vyre_driver::backend::BackendError::DeviceOutOfMemory {
            requested,
            available,
        } => {
            assert_eq!(requested, 132_096);
            assert_eq!(available, 64 * 1024);
        }
        other => panic!("expected DeviceOutOfMemory for budget overflow, got {other:?}"),
    }
}

#[test]
fn device_memory_budget_infers_pressure_without_manual_bps() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 1024,
            requested_worker_groups: 128,
            max_workgroup_size_x: 256,
            resident_device_bytes: 900_000,
            device_memory_budget_bytes: 1_000_000,
            ..MegakernelLaunchRequest::direct(1024, 128, 256)
        })
        .expect("Fix: budget-aware policy should accept launches under the byte budget");

    assert_eq!(rec.topology, MegakernelDispatchTopology::MemoryConstrained);
    assert!(
        rec.worker_groups < 128,
        "inferred memory pressure must shed worker groups before launch"
    );
    assert_eq!(rec.estimated_peak_device_bytes, 916_384);
    assert_eq!(rec.device_memory_budget_bytes, 1_000_000);
}

#[test]
fn dense_frontier_without_hot_fusion_stays_dense() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 16_384,
            requested_worker_groups: 128,
            max_workgroup_size_x: 256,
            graph_node_count: 16_384,
            graph_edge_count: 250_000,
            frontier_density_bps: policy.dense_frontier_threshold_bps,
            ..MegakernelLaunchRequest::direct(16_384, 128, 256)
        })
        .expect("Fix: dense topology should accept valid adapter limits");

    assert_eq!(rec.topology, MegakernelDispatchTopology::DenseFrontier);
}

#[test]
fn mid_density_frontier_selects_hybrid_topology() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 8192,
            requested_worker_groups: 128,
            max_workgroup_size_x: 256,
            graph_node_count: 8192,
            graph_edge_count: 32_768,
            frontier_density_bps: policy.sparse_frontier_threshold_bps + 1,
            ..MegakernelLaunchRequest::direct(8192, 128, 256)
        })
        .expect("Fix: hybrid topology should accept valid adapter limits");

    assert_eq!(rec.topology, MegakernelDispatchTopology::HybridFrontier);
}

#[test]
fn stable_recommendation_holds_sparse_topology_inside_frontier_hysteresis() {
    let policy = MegakernelLaunchPolicy::standard();
    let request = MegakernelLaunchRequest {
        queue_len: 8_192,
        requested_worker_groups: 128,
        max_workgroup_size_x: 256,
        graph_node_count: 100_000,
        graph_edge_count: 250_000,
        frontier_density_bps: policy.sparse_frontier_threshold_bps + 125,
        ..MegakernelLaunchRequest::direct(8_192, 128, 256)
    };
    let stateless = policy
        .recommend(request)
        .expect("Fix: stateless launch recommendation should accept valid adapter limits");
    let stable = policy
        .recommend_with_previous_topology(request, MegakernelDispatchTopology::SparseFrontier)
        .expect("Fix: stable launch recommendation should accept valid adapter limits");

    assert_eq!(
        stateless.topology,
        MegakernelDispatchTopology::HybridFrontier
    );
    assert_eq!(stable.topology, MegakernelDispatchTopology::SparseFrontier);
}

#[test]
fn stable_recommendation_releases_sparse_topology_outside_frontier_hysteresis() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend_with_previous_topology(
            MegakernelLaunchRequest {
                queue_len: 8_192,
                requested_worker_groups: 128,
                max_workgroup_size_x: 256,
                graph_node_count: 100_000,
                graph_edge_count: 250_000,
                frontier_density_bps: policy.sparse_frontier_threshold_bps + 300,
                ..MegakernelLaunchRequest::direct(8_192, 128, 256)
            },
            MegakernelDispatchTopology::SparseFrontier,
        )
        .expect("Fix: stable launch recommendation should accept valid adapter limits");

    assert_eq!(rec.topology, MegakernelDispatchTopology::HybridFrontier);
}

#[test]
fn stable_recommendation_holds_hybrid_topology_inside_sparse_hysteresis() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend_with_previous_topology(
            MegakernelLaunchRequest {
                queue_len: 8_192,
                requested_worker_groups: 128,
                max_workgroup_size_x: 256,
                graph_node_count: 100_000,
                graph_edge_count: 250_000,
                frontier_density_bps: policy.sparse_frontier_threshold_bps - 125,
                ..MegakernelLaunchRequest::direct(8_192, 128, 256)
            },
            MegakernelDispatchTopology::HybridFrontier,
        )
        .expect("Fix: stable launch recommendation should accept valid adapter limits");

    assert_eq!(rec.topology, MegakernelDispatchTopology::HybridFrontier);
}

#[test]
fn stable_recommendation_holds_hybrid_topology_inside_dense_hysteresis() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend_with_previous_topology(
            MegakernelLaunchRequest {
                queue_len: 16_384,
                requested_worker_groups: 128,
                max_workgroup_size_x: 256,
                graph_node_count: 16_384,
                graph_edge_count: 250_000,
                frontier_density_bps: policy.dense_frontier_threshold_bps + 125,
                ..MegakernelLaunchRequest::direct(16_384, 128, 256)
            },
            MegakernelDispatchTopology::HybridFrontier,
        )
        .expect("Fix: stable launch recommendation should accept valid adapter limits");

    assert_eq!(rec.topology, MegakernelDispatchTopology::HybridFrontier);
}

#[test]
fn stable_recommendation_holds_dense_topology_inside_frontier_hysteresis() {
    let policy = MegakernelLaunchPolicy::standard();
    let request = MegakernelLaunchRequest {
        queue_len: 16_384,
        requested_worker_groups: 128,
        max_workgroup_size_x: 256,
        graph_node_count: 16_384,
        graph_edge_count: 250_000,
        frontier_density_bps: policy.dense_frontier_threshold_bps - 125,
        ..MegakernelLaunchRequest::direct(16_384, 128, 256)
    };
    let stateless = policy
        .recommend(request)
        .expect("Fix: stateless launch recommendation should accept valid adapter limits");
    let stable = policy
        .recommend_with_previous_topology(request, MegakernelDispatchTopology::DenseFrontier)
        .expect("Fix: stable launch recommendation should accept valid adapter limits");

    assert_eq!(
        stateless.topology,
        MegakernelDispatchTopology::HybridFrontier
    );
    assert_eq!(stable.topology, MegakernelDispatchTopology::DenseFrontier);
}

#[test]
fn stable_recommendation_preserves_fused_dense_when_hot_graph_stays_near_dense() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend_with_previous_topology(
            MegakernelLaunchRequest {
                queue_len: 131_072,
                requested_worker_groups: 256,
                max_workgroup_size_x: 256,
                graph_node_count: 32_768,
                graph_edge_count: 500_000,
                frontier_density_bps: policy.dense_frontier_threshold_bps - 125,
                hot_window_count: policy.hot_window_threshold,
                ..MegakernelLaunchRequest::direct(131_072, 256, 256)
            },
            MegakernelDispatchTopology::FusedDense,
        )
        .expect("Fix: stable fused dense recommendation should accept valid adapter limits");

    assert_eq!(rec.topology, MegakernelDispatchTopology::FusedDense);
    assert_eq!(rec.execution_mode, MegakernelExecutionMode::Jit);
}

#[test]
fn stable_recommendation_holds_memory_constrained_topology_inside_pressure_hysteresis() {
    let policy = MegakernelLaunchPolicy::standard();
    let request = MegakernelLaunchRequest {
        queue_len: 16_384,
        requested_worker_groups: 128,
        max_workgroup_size_x: 256,
        graph_node_count: 16_384,
        graph_edge_count: 250_000,
        frontier_density_bps: 9_000,
        memory_pressure_bps: policy.memory_pressure_threshold_bps - 125,
        ..MegakernelLaunchRequest::direct(16_384, 128, 256)
    };
    let stateless = policy
        .recommend(request)
        .expect("Fix: stateless launch recommendation should accept valid adapter limits");
    let stable = policy
        .recommend_with_previous_topology(request, MegakernelDispatchTopology::MemoryConstrained)
        .expect("Fix: stable launch recommendation should accept valid adapter limits");

    assert_eq!(
        stateless.topology,
        MegakernelDispatchTopology::DenseFrontier
    );
    assert_eq!(
        stable.topology,
        MegakernelDispatchTopology::MemoryConstrained
    );
    assert!(
        stable.worker_groups < stateless.worker_groups,
        "stable memory-constrained topology must preserve worker shedding near pressure threshold"
    );
}

#[test]
fn missing_frontier_telemetry_infers_density_from_queue_and_graph_scale() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 90_000,
            requested_worker_groups: 256,
            max_workgroup_size_x: 256,
            graph_node_count: 100_000,
            graph_edge_count: 750_000,
            hot_opcode_count: policy.hot_opcode_threshold,
            frontier_density_bps: 0,
            ..MegakernelLaunchRequest::direct(90_000, 256, 256)
        })
        .expect("Fix: inferred-density topology should accept valid adapter limits");

    assert_eq!(rec.topology, MegakernelDispatchTopology::FusedDense);
    assert_eq!(rec.execution_mode, MegakernelExecutionMode::Jit);
}

#[test]
fn sparse_frontier_density_sheds_worker_pressure_without_losing_warp_floor() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 100_000,
            requested_worker_groups: 256,
            max_workgroup_size_x: 256,
            graph_node_count: 1_000_000,
            graph_edge_count: 4_000_000,
            frontier_density_bps: 100,
            ..MegakernelLaunchRequest::direct(100_000, 256, 256)
        })
        .expect("Fix: sparse density worker shedding must accept valid adapter limits");

    assert_eq!(rec.topology, MegakernelDispatchTopology::SparseFrontier);
    assert_eq!(rec.worker_groups, 51);
    assert_eq!(rec.geometry.workgroup_size_x, 51);
    assert_eq!(rec.geometry.dispatch_grid, [51, 1, 1]);
}

#[test]
fn sparse_frontier_worker_shedding_preserves_warp_floor_for_tiny_density() {
    let policy = MegakernelLaunchPolicy::standard();
    let rec = policy
        .recommend(MegakernelLaunchRequest {
            queue_len: 1_000,
            requested_worker_groups: 256,
            max_workgroup_size_x: 256,
            graph_node_count: 1_000_000,
            graph_edge_count: 4_000_000,
            frontier_density_bps: 1,
            ..MegakernelLaunchRequest::direct(1_000, 256, 256)
        })
        .expect("Fix: sparse density worker shedding must retain a useful GPU width");

    assert_eq!(rec.topology, MegakernelDispatchTopology::SparseFrontier);
    assert_eq!(rec.worker_groups, 32);
    assert_eq!(rec.geometry.workgroup_size_x, 32);
}

#[test]
fn launch_cache_update_does_not_duplicate_entries() {
    let policy = MegakernelLaunchPolicy::standard();
    let request = MegakernelLaunchRequest::direct(128, 64, 256);
    let key = LaunchRecommendationCacheKey { policy, request };
    let rec = policy
        .recommend(request)
        .expect("Fix: policy should accept non-zero adapter limits");
    let mut cache = LaunchRecommendationCache::default();

    cache.insert(key, rec);
    cache.insert(key, rec);

    assert_eq!(cache.entries.len(), 1);
}

#[test]

fn launch_cache_get_promotes_hot_key_before_eviction() {
    let policy = MegakernelLaunchPolicy::standard();
    let hot_request = MegakernelLaunchRequest::direct(1, 64, 256);
    let hot_key = LaunchRecommendationCacheKey {
        policy,
        request: hot_request,
    };
    let hot_rec = policy
        .recommend(hot_request)
        .expect("Fix: policy should accept non-zero adapter limits");
    let mut cache = LaunchRecommendationCache::default();

    cache.insert(hot_key, hot_rec);
    for queue_len in 2..=128 {
        let request = MegakernelLaunchRequest::direct(queue_len, 64, 256);
        let rec = policy
            .recommend(request)
            .expect("Fix: policy should accept non-zero adapter limits");
        cache.insert(LaunchRecommendationCacheKey { policy, request }, rec);
    }
    assert!(cache.get(&hot_key).is_some());
    assert_eq!(cache.hits, 1);
    assert_eq!(cache.misses, 0);

    let cold_request = MegakernelLaunchRequest::direct(129, 64, 256);
    let cold_rec = policy
        .recommend(cold_request)
        .expect("Fix: policy should accept non-zero adapter limits");
    cache.insert(
        LaunchRecommendationCacheKey {
            policy,
            request: cold_request,
        },
        cold_rec,
    );

    assert!(cache.get(&hot_key).is_some());
    assert_eq!(cache.hits, 2);
    assert_eq!(cache.entries.len(), 128);
}

#[test]
fn launch_cache_records_misses_without_mutating_capacity() {
    let policy = MegakernelLaunchPolicy::standard();
    let request = MegakernelLaunchRequest::direct(128, 64, 256);
    let missing = LaunchRecommendationCacheKey { policy, request };
    let mut cache = LaunchRecommendationCache::default();

    assert!(cache.get(&missing).is_none());

    assert_eq!(cache.hits, 0);
    assert_eq!(cache.misses, 1);
    assert!(cache.entries.is_empty());
}

#[test]
fn launch_policy_exposes_thread_local_cache_stats() {
    MegakernelLaunchPolicy::reset_launch_cache_for_thread();
    let policy = MegakernelLaunchPolicy::standard();
    let request = MegakernelLaunchRequest::direct(512, 64, 256);

    let initial = MegakernelLaunchPolicy::launch_cache_stats();
    assert_eq!(initial.entries, 0);
    assert_eq!(initial.hits, 0);
    assert_eq!(initial.misses, 0);

    let first = policy
        .recommend(request)
        .expect("Fix: valid policy request must recommend");
    let after_miss = MegakernelLaunchPolicy::launch_cache_stats();
    assert_eq!(after_miss.entries, 1);
    assert_eq!(after_miss.hits, 0);
    assert_eq!(after_miss.misses, 1);

    let second = policy
        .recommend(request)
        .expect("Fix: cached policy request must recommend");
    let after_hit = MegakernelLaunchPolicy::launch_cache_stats();
    assert_eq!(first, second);
    assert_eq!(after_hit.entries, 1);
    assert_eq!(after_hit.hits, 1);
    assert_eq!(after_hit.misses, 1);

    MegakernelLaunchPolicy::reset_launch_cache_for_thread();
}

#[test]
fn diffuse_priority_mismatched_restrictions_preserve_input_shape() {
    let input = [3.0, 1.0, 2.0];
    let restrictions = [1.0, 0.5];
    let mut out = Vec::with_capacity(input.len());
    let mut scratch = Vec::with_capacity(input.len());

    diffuse_priority_across_siblings_into(&input, &restrictions, 0.5, 4, &mut out, &mut scratch);

    assert_eq!(out, input);
    assert!(scratch.is_empty());
    assert_eq!(out.capacity(), input.len());
}

#[test]
fn diffuse_priority_reuses_exact_scratch_capacity() {
    let input = [4.0, 2.0, 1.0];
    let restrictions = [1.0, 1.0, 1.0];
    let mut out = Vec::with_capacity(input.len());
    let mut scratch = Vec::with_capacity(input.len());
    let out_ptr = out.as_ptr();
    let scratch_ptr = scratch.as_ptr();

    diffuse_priority_across_siblings_into(&input, &restrictions, 0.25, 2, &mut out, &mut scratch);

    assert_eq!(out.len(), input.len());
    assert_eq!(scratch.len(), input.len());
    assert_eq!(out.capacity(), input.len());
    assert_eq!(scratch.capacity(), input.len());
    assert_eq!(out.as_ptr(), out_ptr);
    assert_eq!(scratch.as_ptr(), scratch_ptr);
}


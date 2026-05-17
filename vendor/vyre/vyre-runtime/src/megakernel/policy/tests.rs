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
    assert!(rec.promote_hot_opcodes);
    assert!(rec.age_priority_work);
}

#[test]
fn launch_cache_update_does_not_duplicate_order_entries() {
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
    assert_eq!(cache.order.len(), 1);
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

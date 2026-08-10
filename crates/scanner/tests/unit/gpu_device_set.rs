use super::*;

fn exposure(api: GpuApi, ordinal: usize, physical: &str, topology: &str) -> GpuDeviceExposure {
    GpuDeviceExposure {
        api,
        api_ordinal: ordinal,
        physical_identity: physical.to_string(),
        topology_identity: topology.to_string(),
        name: format!("device-{physical}"),
        vendor_id: 0x10de,
        device_id: 0x1234,
        driver_identity: "driver-1".to_string(),
        runtime_identity: match api {
            GpuApi::Wgpu => "wgpu-25/vyre-0.7.2".to_string(),
            _ => format!("runtime-{api:?}"),
        },
        capacity_bytes: 8 << 30,
        is_software: false,
        is_display_only: false,
        ineligible_reason: None,
    }
}

fn device(ordinal: usize, physical: &str, weight: u64, budget: u64) -> CalibratedGpuDevice {
    CalibratedGpuDevice {
        api: GpuApi::Wgpu,
        api_ordinal: ordinal,
        physical_identity: physical.to_string(),
        topology_identity: format!("pci:0000:{ordinal:02x}:00.0/numa:0"),
        name: format!("device-{physical}"),
        vendor_id: 0x10de,
        device_id: 0x1234,
        software_eligible: true,
        display_eligible: true,
        driver_identity: "driver-1".to_string(),
        runtime_identity: "wgpu-25/vyre-0.7.2".to_string(),
        capacity_bytes: 8 << 30,
        workload_weight: weight,
        timing: DeviceTimingEvidence {
            sample_bytes: 8 << 20,
            trials_ns: vec![100, 101, 99],
        },
        resident_budget_bytes: budget,
    }
}

fn route(weights: &[u64]) -> OrderedGpuDeviceRoute {
    OrderedGpuDeviceRoute::new(
        "workload-a".to_string(),
        "detectors-a".to_string(),
        "config-a".to_string(),
        4 << 30,
        weights
            .iter()
            .enumerate()
            .map(|(index, weight)| device(index, &format!("gpu-{index}"), *weight, 1 << 30))
            .collect(),
    )
    .expect("valid route")
}

#[test]
fn duplicate_api_exposure_is_retained_with_explicit_reason() {
    let census = deduplicate_gpu_exposures(vec![
        exposure(GpuApi::Wgpu, 0, "gpu-a", "vulkan:adapter-0"),
        exposure(GpuApi::Cuda, 0, "gpu-a", "pci:0000:01:00.0"),
        exposure(GpuApi::Wgpu, 1, "gpu-b", "pci:0000:02:00.0"),
    ])
    .expect("census");
    assert_eq!(census.eligible.len(), 2);
    let selected = census
        .eligible
        .iter()
        .map(|index| census.exposures[*index].api)
        .collect::<Vec<_>>();
    assert_eq!(selected, vec![GpuApi::Cuda, GpuApi::Wgpu]);
    let duplicate = census
        .exposures
        .iter()
        .find(|row| row.physical_identity == "gpu-a" && row.api == GpuApi::Wgpu)
        .expect("duplicate row retained");
    assert!(duplicate
        .ineligible_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("duplicate API exposure")));
}

#[test]
fn software_display_and_incomplete_adapters_have_specific_reasons() {
    let mut software = exposure(GpuApi::Wgpu, 0, "soft", "virtual:soft");
    software.is_software = true;
    let mut display = exposure(GpuApi::Wgpu, 1, "display", "pci:display");
    display.is_display_only = true;
    let mut missing = exposure(GpuApi::Cuda, 0, "", "");
    missing.capacity_bytes = 0;
    let census = deduplicate_gpu_exposures(vec![software, display, missing]).expect("census");
    assert!(census.eligible.is_empty());
    let reasons = census
        .exposures
        .iter()
        .map(|row| row.ineligible_reason.as_deref().expect("reason"))
        .collect::<Vec<_>>();
    assert!(reasons
        .iter()
        .any(|reason| reason.contains("software adapter")));
    assert!(reasons.iter().any(|reason| reason.contains("display-only")));
    assert!(reasons
        .iter()
        .any(|reason| reason.contains("physical adapter identity")));
}

#[test]
fn identical_devices_are_stably_balanced_without_splitting_shards() {
    let route = route(&[1, 1]);
    let shards = (0..8)
        .map(|index| ExactShard { index, bytes: 64 })
        .collect::<Vec<_>>();
    let first = partition_exact_shards(&route, &shards).expect("partition");
    let second = partition_exact_shards(&route, &shards).expect("partition");
    assert_eq!(first, second);
    let WeightedShardPlan::MultiDevice(assignments) = first else {
        panic!("two-device route must partition")
    };
    assert_eq!(
        assignments
            .iter()
            .map(|assignment| assignment.device_index)
            .collect::<Vec<_>>(),
        vec![0, 0, 0, 0, 1, 1, 1, 1]
    );
}

#[test]
fn asymmetric_weights_use_only_persisted_integer_evidence() {
    let route = route(&[1, 3]);
    let shards = (0..8)
        .map(|index| ExactShard { index, bytes: 1 })
        .collect::<Vec<_>>();
    let WeightedShardPlan::MultiDevice(plan) =
        partition_exact_shards(&route, &shards).expect("partition")
    else {
        panic!("two-device route must partition")
    };
    let counts = plan.iter().fold([0usize; 2], |mut counts, assignment| {
        counts[assignment.device_index] += 1;
        counts
    });
    assert_eq!(counts, [2, 6]);
    assert!(
        plan.windows(2)
            .all(|pair| pair[0].device_index <= pair[1].device_index),
        "each device must own one contiguous shard range"
    );
}

#[test]
fn device_set_identity_ignores_measurements_but_rejects_hardware_drift() {
    let baseline = route(&[1, 3]);
    let remeasured = route(&[2, 5]);
    assert!(baseline.has_same_device_set_identity(&remeasured));
    assert_eq!(
        baseline.device_set_identity_digest(),
        remeasured.device_set_identity_digest()
    );

    let mut changed_devices = remeasured.devices.clone();
    changed_devices[1].driver_identity = "driver-2".to_string();
    let changed = OrderedGpuDeviceRoute::new(
        remeasured.workload_identity.clone(),
        remeasured.detector_digest.clone(),
        remeasured.config_digest.clone(),
        remeasured.process_resident_limit_bytes,
        changed_devices,
    )
    .expect("changed hardware route remains structurally valid");
    assert!(!baseline.has_same_device_set_identity(&changed));
    assert_ne!(
        baseline.device_set_identity_digest(),
        changed.device_set_identity_digest()
    );
}

#[test]
fn zero_bytes_huge_shard_and_many_tiny_shards_remain_bounded_and_deterministic() {
    let route = route(&[2, 1]);
    let empty = partition_exact_shards(&route, &[]).expect("zero-byte input");
    assert_eq!(empty, WeightedShardPlan::MultiDevice(Vec::new()));

    let huge = [ExactShard {
        index: 77,
        bytes: u64::MAX,
    }];
    assert_eq!(
        partition_exact_shards(&route, &huge).expect("one exact huge shard"),
        WeightedShardPlan::MultiDevice(vec![ShardAssignment {
            shard_index: 77,
            device_index: 0,
        }])
    );

    let tiny = (0..MAX_GPU_ROUTE_SHARDS)
        .map(|index| ExactShard { index, bytes: 1 })
        .collect::<Vec<_>>();
    let first = partition_exact_shards(&route, &tiny).expect("maximum tiny-shard partition");
    let second =
        partition_exact_shards(&route, &tiny).expect("maximum tiny-shard partition replay");
    assert_eq!(first, second);
    let mut over = tiny;
    over.push(ExactShard {
        index: MAX_GPU_ROUTE_SHARDS,
        bytes: 1,
    });
    assert!(partition_exact_shards(&route, &over)
        .expect_err("over-limit shard count rejected")
        .contains("above the bounded limit"));
}

#[test]
fn single_device_route_borrows_exact_shards_without_hot_path_allocation() {
    let route = route(&[7]);
    let shards = [ExactShard {
        index: 4,
        bytes: 99,
    }];
    let WeightedShardPlan::SingleDevice(borrowed) =
        partition_exact_shards(&route, &shards).expect("single route")
    else {
        panic!("single-device route must not allocate a plan")
    };
    assert!(std::ptr::eq(borrowed.as_ptr(), shards.as_ptr()));
}

#[test]
fn reordered_partial_stale_and_tampered_live_sets_fail_before_scheduling() {
    let route = route(&[1, 1]);
    let live = deduplicate_gpu_exposures(vec![
        exposure(GpuApi::Wgpu, 0, "gpu-0", "pci:0000:00:00.0/numa:0"),
        exposure(GpuApi::Wgpu, 1, "gpu-1", "pci:0000:01:00.0/numa:0"),
    ])
    .expect("live census");
    assert!(route.validate_live_set(&live).is_ok());

    let reordered = GpuAdapterCensus {
        exposures: live.exposures.clone(),
        eligible: live.eligible.iter().copied().rev().collect(),
        failures: live.failures.clone(),
    };
    assert!(route
        .validate_live_set(&reordered)
        .expect_err("order change rejected")
        .contains("ordered position 0"));

    let partial = GpuAdapterCensus {
        exposures: live.exposures.clone(),
        eligible: vec![live.eligible[0]],
        failures: live.failures.clone(),
    };
    assert!(route
        .validate_live_set(&partial)
        .expect_err("partial set rejected")
        .contains("requires 2 device"));

    let mut stale = route.clone();
    stale.schema_version = 1;
    assert!(stale
        .validate()
        .expect_err("v1 route without authenticated adapter identity rejected")
        .contains("unsupported GPU device route schema 1; expected 2"));

    let mut tampered = route.clone();
    tampered.devices[0].workload_weight = 99;
    assert!(tampered
        .validate()
        .expect_err("tampered route rejected")
        .contains("authentication digest mismatch"));

    let mut duplicate_physical = route.clone();
    duplicate_physical.devices[1].physical_identity =
        duplicate_physical.devices[0].physical_identity.clone();
    assert_ne!(
        duplicate_physical.devices[1].topology_identity,
        duplicate_physical.devices[0].topology_identity
    );
    duplicate_physical.authenticated_digest = duplicate_physical.compute_digest();
    assert!(duplicate_physical
        .validate()
        .expect_err("one physical GPU cannot enter through divergent topology labels")
        .contains("duplicate physical adapter"));
}

#[test]
fn resident_budgets_are_derived_from_capacity_and_process_ceiling() {
    assert_eq!(
        derive_resident_budgets(&[8, 4], 6).expect("asymmetric budgets"),
        vec![4, 2]
    );
    assert_eq!(
        derive_resident_budgets(&[1, 1, 100], 3).expect("minimum bounded budgets"),
        vec![1, 1, 1]
    );
    assert_eq!(
        derive_resident_budgets(&[8, 4], 99).expect("capacity-capped budgets"),
        vec![8, 4]
    );
    assert!(derive_resident_budgets(&[8, 4], 1)
        .expect_err("process ceiling below device count")
        .contains("at least one process byte"));
}

/// WHY: completion order must not change the logical source/shard ordering.
#[test]
fn retirement_restores_source_order_after_reverse_completion() {
    let rows = (0..10_000)
        .map(|index| vec![index * 3, index * 3 + 1, index * 3 + 2])
        .collect::<Vec<_>>();
    let scalar = rows.iter().flatten().copied().collect::<Vec<_>>();
    let mut retirement = DeterministicRetirement::new(rows.len()).expect("retirement");
    for index in (0..rows.len()).rev() {
        retirement
            .record_success(index, rows[index].clone())
            .expect("retire out of order");
    }
    let merged = retirement
        .finish()
        .expect("complete retirement")
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(merged, scalar);
}

#[test]
fn every_required_device_failure_invalidates_complete_route() {
    for device_index in 0..3 {
        for phase in ["submit", "retire", "cancellation"] {
            let mut retirement = DeterministicRetirement::new(3).expect("retirement");
            for shard in 0..3 {
                retirement
                    .record_success(shard, shard)
                    .expect("sibling success before failure");
            }
            retirement.record_failure(device_index, phase, "injected fault");
            let error = retirement.finish().expect_err("whole route must fail");
            assert!(error.contains(&format!("device {device_index} {phase} failed")));
            assert!(error.contains("ordered device-set route is invalid"));
        }
    }
}

#[test]
fn incomplete_retirement_is_visible() {
    let mut incomplete = DeterministicRetirement::new(2).expect("retirement");
    incomplete.record_success(1, 2).expect("second shard");
    assert!(incomplete
        .finish()
        .expect_err("missing shard fails")
        .contains("missing retired shard 0"));
}

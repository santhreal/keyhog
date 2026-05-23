// Tests for `telemetry.rs`. Split out per audit item #85 to keep the
// parent file focused on production code.

use super::*;
use crate::megakernel::descriptor::WindowClass;
use crate::megakernel::protocol::{opcode, SLOT_WORDS};
use crate::megakernel::Megakernel;
use crate::megakernel::{
    MegakernelDispatchTopology, MegakernelExecutionMode, MegakernelLaunchRequest,
};

#[test]
fn decode_empty_ring_counts_slots() {
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let ring = Megakernel::try_encode_empty_ring(4).unwrap();
    let telemetry = RingTelemetry::decode(&control, &ring);
    assert_eq!(telemetry.occupancy.empty, 4);
    assert_eq!(telemetry.occupancy.published, 0);
    assert_eq!(telemetry.slots.len(), 4);
    assert!(telemetry.windows.is_empty());
}

#[test]
fn strict_decode_rejects_trailing_partial_slot() {
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let mut ring = Megakernel::try_encode_empty_ring(1).unwrap();
    ring.push(0);
    let err = RingTelemetry::try_decode(&control, &ring)
        .expect_err("Fix: strict telemetry must reject malformed ring snapshots");
    assert!(matches!(err, PipelineError::Backend(_)));
}

#[test]
fn strict_decode_rejects_misaligned_control_snapshot() {
    let mut control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    control.push(0xFF);
    let ring = Megakernel::try_encode_empty_ring(1).unwrap();
    let err = RingTelemetry::try_decode(&control, &ring)
        .expect_err("Fix: strict telemetry must reject malformed control snapshots");
    assert!(matches!(err, PipelineError::Backend(_)));
}

#[test]
fn decode_published_slot_reads_prefix() {
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let mut ring = Megakernel::try_encode_empty_ring(2).unwrap();
    Megakernel::publish_slot(&mut ring, 1, 9, opcode::ATOMIC_ADD, &[5, 7, 11]).unwrap();
    let telemetry = RingTelemetry::decode(&control, &ring);
    let slot = &telemetry.slots[1];
    assert_eq!(slot.status, RingStatus::Published);
    assert_eq!(slot.tenant_id, 9);
    assert_eq!(slot.opcode, opcode::ATOMIC_ADD);
    assert_eq!(slot.args_prefix, [5, 7, 11]);
}

#[test]
fn decode_window_opcodes_groups_ticketed_slots() {
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
    let window_opcode = 0xF101;
    Megakernel::publish_slot(
        &mut ring,
        0,
        3,
        window_opcode,
        &[7, WindowClass::Required.into_wire(), 42],
    )
    .unwrap();
    Megakernel::publish_slot(
        &mut ring,
        1,
        3,
        window_opcode,
        &[7, WindowClass::Lookahead.into_wire(), 99],
    )
    .unwrap();
    Megakernel::publish_slot(
        &mut ring,
        2,
        3,
        window_opcode,
        &[7, WindowClass::Required.into_wire(), 123],
    )
    .unwrap();
    let telemetry = RingTelemetry::decode_with_window_opcodes(&control, &ring, &[window_opcode]);
    assert_eq!(telemetry.windows.len(), 1);
    let window = &telemetry.windows[0];
    assert_eq!(window.ticket, 7);
    assert_eq!(window.tenant_id, 3);
    assert_eq!(window.opcode, window_opcode);
    assert_eq!(window.required_slots, 2);
    assert_eq!(window.lookahead_slots, 1);
    assert_eq!(window.published, 3);
    assert!(window.is_active());
    assert_eq!(telemetry.active_windows().len(), 1);
    assert_eq!(telemetry.active_slots_for_opcode(window_opcode).len(), 3);
    assert_eq!(
        telemetry
            .active_slots_for_opcode_iter(window_opcode)
            .count(),
        3
    );
    let mut active_windows = Vec::with_capacity(4);
    let mut active_slots = Vec::with_capacity(4);
    let windows_ptr = active_windows.as_ptr();
    let slots_ptr = active_slots.as_ptr();
    telemetry.active_windows_into(&mut active_windows);
    telemetry.active_slots_for_opcode_into(window_opcode, &mut active_slots);
    assert_eq!(active_windows.len(), 1);
    assert_eq!(active_slots.len(), 3);
    assert_eq!(active_windows.as_ptr(), windows_ptr);
    assert_eq!(active_slots.as_ptr(), slots_ptr);
}

#[test]
fn decode_window_opcodes_matches_dense_bitmap_opcodes() {
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
    let first_window_opcode = 3u32;
    let second_window_opcode = 9u32;
    Megakernel::publish_slot(
        &mut ring,
        0,
        3,
        first_window_opcode,
        &[11, WindowClass::Required.into_wire(), 42],
    )
    .unwrap();
    Megakernel::publish_slot(
        &mut ring,
        1,
        3,
        second_window_opcode,
        &[11, WindowClass::Lookahead.into_wire(), 99],
    )
    .unwrap();
    let telemetry = RingTelemetry::decode_with_window_opcodes(
        &control,
        &ring,
        &[first_window_opcode, second_window_opcode],
    );
    assert_eq!(telemetry.windows.len(), 2);
    assert_eq!(
        telemetry.active_slots_for_opcode(first_window_opcode).len(),
        1
    );
    assert_eq!(
        telemetry.active_slots_for_opcode(second_window_opcode).len(),
        1
    );
}

#[test]
fn decode_with_scratch_reuses_snapshot_storage() {
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
    let window_opcode = 0xF101;
    Megakernel::publish_slot(
        &mut ring,
        0,
        3,
        window_opcode,
        &[7, WindowClass::Required.into_wire(), 42],
    )
    .unwrap();
    Megakernel::publish_slot(
        &mut ring,
        1,
        3,
        window_opcode,
        &[7, WindowClass::Lookahead.into_wire(), 99],
    )
    .unwrap();

    let mut telemetry = RingTelemetry {
        control: ControlSnapshot {
            metrics: Vec::with_capacity(control::METRICS_SLOTS as usize),
            tenant_fairness: Vec::with_capacity(control::TENANT_FAIRNESS_SLOTS as usize),
            priority_fairness: Vec::with_capacity(control::PRIORITY_FAIRNESS_SLOTS as usize),
            ..ControlSnapshot::default()
        },
        slots: Vec::with_capacity(4),
        windows: Vec::with_capacity(1),
        ..RingTelemetry::default()
    };
    let mut scratch = TelemetryDecodeScratch::new();

    RingTelemetry::decode_with_window_opcodes_into(
        &control,
        &ring,
        &[window_opcode],
        &mut telemetry,
        &mut scratch,
    );
    let metrics_ptr = telemetry.control.metrics.as_ptr();
    let tenant_ptr = telemetry.control.tenant_fairness.as_ptr();
    let priority_ptr = telemetry.control.priority_fairness.as_ptr();
    let slots_ptr = telemetry.slots.as_ptr();
    let windows_ptr = telemetry.windows.as_ptr();

    RingTelemetry::try_decode_with_window_opcodes_into(
        &control,
        &ring,
        &[window_opcode],
        &mut telemetry,
        &mut scratch,
    )
    .expect("Fix: scratch telemetry decode must accept valid control/ring snapshots");

    assert_eq!(telemetry.control.metrics.as_ptr(), metrics_ptr);
    assert_eq!(telemetry.control.tenant_fairness.as_ptr(), tenant_ptr);
    assert_eq!(telemetry.control.priority_fairness.as_ptr(), priority_ptr);
    assert_eq!(telemetry.slots.as_ptr(), slots_ptr);
    assert_eq!(telemetry.windows.as_ptr(), windows_ptr);
    assert_eq!(telemetry.windows.len(), 1);
    assert_eq!(telemetry.slots.len(), 4);
}

#[test]
fn decode_sorted_window_opcodes_reuses_scratch_without_resort_growth() {
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
    let first_opcode = 0xF101;
    let second_opcode = 0xF102;
    Megakernel::publish_slot(
        &mut ring,
        0,
        3,
        first_opcode,
        &[7, WindowClass::Required.into_wire(), 42],
    )
    .unwrap();
    Megakernel::publish_slot(
        &mut ring,
        1,
        3,
        second_opcode,
        &[9, WindowClass::Lookahead.into_wire(), 99],
    )
    .unwrap();

    let mut telemetry = RingTelemetry::default();
    let mut scratch = TelemetryDecodeScratch::new();
    let sorted_unique = [first_opcode, second_opcode];
    RingTelemetry::decode_with_window_opcodes_into(
        &control,
        &ring,
        &sorted_unique,
        &mut telemetry,
        &mut scratch,
    );
    let opcode_capacity = scratch.window_opcodes.capacity();
    let window_capacity = scratch.windows.capacity();

    RingTelemetry::decode_with_window_opcodes_into(
        &control,
        &ring,
        &sorted_unique,
        &mut telemetry,
        &mut scratch,
    );

    assert_eq!(scratch.window_opcodes.capacity(), opcode_capacity);
    assert_eq!(scratch.windows.capacity(), window_capacity);
    assert_eq!(telemetry.windows.len(), 2);
    assert!(
        telemetry
            .windows
            .iter()
            .any(|window| window.opcode == first_opcode && window.ticket == 7)
    );
    assert!(
        telemetry
            .windows
            .iter()
            .any(|window| window.opcode == second_opcode && window.ticket == 9)
    );
}

#[test]
fn terminal_window_is_not_reported_as_active() {
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let mut ring = Megakernel::try_encode_empty_ring(2).unwrap();
    let window_opcode = 0xF101;
    Megakernel::publish_slot(
        &mut ring,
        0,
        3,
        window_opcode,
        &[9, WindowClass::Required.into_wire(), 42],
    )
    .unwrap();
    Megakernel::publish_slot(
        &mut ring,
        1,
        3,
        window_opcode,
        &[9, WindowClass::Lookahead.into_wire(), 99],
    )
    .unwrap();
    let mut mark_done = |slot_idx: usize| {
        let start = slot_idx * (SLOT_WORDS as usize) * 4 + (STATUS_WORD as usize) * 4;
        ring[start..start + 4].copy_from_slice(&slot::DONE.to_le_bytes());
    };
    mark_done(0);
    mark_done(1);
    let telemetry = RingTelemetry::decode_with_window_opcodes(&control, &ring, &[window_opcode]);
    assert_eq!(telemetry.windows.len(), 1);
    assert!(!telemetry.windows[0].is_active());
    assert!(telemetry.active_windows().is_empty());
    assert!(telemetry.active_slots_for_opcode(window_opcode).is_empty());
}

#[test]
fn telemetry_recommendation_promotes_hot_opcodes_and_requeue_pressure() {
    let mut control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    for opcode_idx in 0..8u32 {
        let off = ((control::METRICS_BASE + opcode_idx) as usize) * 4;
        control[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
    }
    let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
    let status_off = (STATUS_WORD as usize) * 4;
    ring[status_off..status_off + 4].copy_from_slice(&slot::REQUEUE.to_le_bytes());
    let telemetry = RingTelemetry::decode(&control, &ring);
    let rec = telemetry
        .recommend_launch(MegakernelLaunchRequest::direct(4096, 64, 256))
        .expect("Fix: telemetry launch recommendation must accept valid limits");
    assert_eq!(rec.execution_mode, MegakernelExecutionMode::Jit);
    assert!(rec.promote_hot_opcodes);
    assert!(rec.age_priority_work);
    assert_eq!(telemetry.priority_accounting().requeue_count, 1);
}

#[test]
fn runtime_counters_report_queue_idle_fairness_and_drain() {
    let mut control = Megakernel::try_encode_control(false, 7, 0).unwrap();
    let tenant_a = (control::TENANT_FAIRNESS_BASE as usize) * 4;
    let tenant_b = ((control::TENANT_FAIRNESS_BASE + 1) as usize) * 4;
    let priority_a = (control::PRIORITY_FAIRNESS_BASE as usize) * 4;
    let done_count = (control::DONE_COUNT as usize) * 4;
    control[done_count..done_count + 4].copy_from_slice(&7u32.to_le_bytes());
    control[tenant_a..tenant_a + 4].copy_from_slice(&3u32.to_le_bytes());
    control[tenant_b..tenant_b + 4].copy_from_slice(&9u32.to_le_bytes());
    control[priority_a..priority_a + 4].copy_from_slice(&5u32.to_le_bytes());

    let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
    Megakernel::publish_slot(&mut ring, 2, 11, opcode::ATOMIC_ADD, &[1, 2, 3]).unwrap();
    let slot_status =
        |slot_idx: usize| slot_idx * (SLOT_WORDS as usize) * 4 + (STATUS_WORD as usize) * 4;
    let requeue = slot_status(0);
    ring[requeue..requeue + 4].copy_from_slice(&slot::REQUEUE.to_le_bytes());
    let done = slot_status(1);
    ring[done..done + 4].copy_from_slice(&slot::DONE.to_le_bytes());

    let counters = RingTelemetry::decode(&control, &ring).runtime_counters();
    assert_eq!(counters.total_slots, 4);
    assert_eq!(counters.queue_depth, 2);
    assert_eq!(counters.gpu_idle_slots, 1);
    assert_eq!(counters.gpu_idle_ppm, 250_000);
    assert_eq!(counters.frontier_density_bps, 5_000);
    assert_eq!(counters.occupancy_proxy_bps, 7_500);
    assert_eq!(counters.drained_slots, 7);
    assert_eq!(counters.unreclaimed_done_slots, 1);
    assert_eq!(counters.tenant_fairness_total, 12);
    assert_eq!(counters.tenant_fairness_skew, 6);
    assert_eq!(counters.priority_fairness_total, 5);
    assert_eq!(counters.requeue_slots, 1);
}

#[test]
fn telemetry_launch_recommendation_uses_frontier_density_for_topology() {
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let mut ring = Megakernel::try_encode_empty_ring(8).unwrap();
    Megakernel::publish_slot(&mut ring, 0, 7, opcode::ATOMIC_ADD, &[1, 2, 3]).unwrap();
    Megakernel::publish_slot(&mut ring, 1, 7, opcode::ATOMIC_ADD, &[1, 2, 3]).unwrap();
    Megakernel::publish_slot(&mut ring, 2, 7, opcode::ATOMIC_ADD, &[1, 2, 3]).unwrap();
    Megakernel::publish_slot(&mut ring, 3, 7, opcode::ATOMIC_ADD, &[1, 2, 3]).unwrap();

    let telemetry = RingTelemetry::decode(&control, &ring);
    let rec = telemetry
        .recommend_launch(MegakernelLaunchRequest::direct(8, 64, 256))
        .expect("Fix: telemetry launch recommendation must accept valid limits");

    assert_eq!(telemetry.runtime_counters().frontier_density_bps, 5_000);
    assert_eq!(rec.topology, MegakernelDispatchTopology::DenseFrontier);
}

#[test]
fn sketch_into_reuses_counter_storage() {
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
    Megakernel::publish_slot(&mut ring, 1, 9, opcode::ATOMIC_ADD, &[5, 7, 11]).unwrap();
    let telemetry = RingTelemetry::decode(&control, &ring);
    let mut scratch = SketchTelemetryScratch::new(3, 16).unwrap();

    telemetry.sketch_into(3, 16, &mut scratch).unwrap();
    let ring_ptr = scratch.ring_opcode.counters().as_ptr();
    let active_ptr = scratch.active_opcode.counters().as_ptr();
    let tenant_ptr = scratch.tenant.counters().as_ptr();
    let status_ptr = scratch.status.counters().as_ptr();
    let metrics_ptr = scratch.dispatch_metrics.counters().as_ptr();
    let first_active = scratch.active_slots;

    telemetry.sketch_into(3, 16, &mut scratch).unwrap();

    assert_eq!(scratch.ring_opcode.counters().as_ptr(), ring_ptr);
    assert_eq!(scratch.active_opcode.counters().as_ptr(), active_ptr);
    assert_eq!(scratch.tenant.counters().as_ptr(), tenant_ptr);
    assert_eq!(scratch.status.counters().as_ptr(), status_ptr);
    assert_eq!(scratch.dispatch_metrics.counters().as_ptr(), metrics_ptr);
    assert_eq!(scratch.total_slots, 4);
    assert_eq!(scratch.active_slots, first_active);
    assert!(scratch.ring_opcode.estimate(opcode::ATOMIC_ADD) >= 1);
}

#[test]
fn watchdog_health_flags_active_queue_without_drain_progress() {
    let mut previous_control = Megakernel::try_encode_control(false, 7, 0).unwrap();
    let done_count = (control::DONE_COUNT as usize) * 4;
    previous_control[done_count..done_count + 4].copy_from_slice(&7u32.to_le_bytes());
    let previous_ring = Megakernel::try_encode_empty_ring(2).unwrap();
    let previous = RingTelemetry::decode(&previous_control, &previous_ring);

    let mut current_control = previous_control.clone();
    let mut current_ring = Megakernel::try_encode_empty_ring(2).unwrap();
    Megakernel::publish_slot(&mut current_ring, 0, 7, opcode::ATOMIC_ADD, &[1, 2, 3]).unwrap();
    let stalled = RingTelemetry::decode(&current_control, &current_ring).health_since(&previous);
    assert_eq!(stalled.done_delta, 0);
    assert_eq!(stalled.queue_depth, 1);
    assert!(stalled.suspected_stall);

    current_control[done_count..done_count + 4].copy_from_slice(&9u32.to_le_bytes());
    let progressed = RingTelemetry::decode(&current_control, &current_ring).health_since(&previous);
    assert_eq!(progressed.done_delta, 2);
    assert!(!progressed.suspected_stall);
}

#[test]
fn metrics_and_observable_regions_remain_non_overlapping_in_snapshot() {
    let mut control = Megakernel::try_encode_control(false, 1, 4).unwrap();
    let metric_off = (control::METRICS_BASE as usize) * 4;
    control[metric_off..metric_off + 4].copy_from_slice(&0xAA55AA55u32.to_le_bytes());
    let observable_off = (control::OBSERVABLE_BASE as usize) * 4;
    control[observable_off..observable_off + 4].copy_from_slice(&0x11223344u32.to_le_bytes());

    let ring = Megakernel::try_encode_empty_ring(1).unwrap();
    let telemetry = RingTelemetry::decode(&control, &ring);
    assert!(
        telemetry.control.metrics.contains(&(0, 0xAA55AA55)),
        "metrics decoder must preserve metric slot 0 value"
    );
    assert_eq!(
        Megakernel::read_observable(&control, 0),
        0x11223344,
        "observable reads must not alias metric region words"
    );
}

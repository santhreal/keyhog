use super::{
    reset_resident_literal_slot, scan_gpu_literal_evidence_by_region_resident,
    GpuResidentLiteralSlot,
};

/// Regression: calibration must preserve the diagnostic when a prior GPU cleanup poisoned the slot.
#[test]
fn calibration_reset_preserves_an_unhealthy_resident_slot() {
    let slot = std::sync::Mutex::new(GpuResidentLiteralSlot::Failed(
        "driver cleanup fault".to_string(),
    ));

    let error = reset_resident_literal_slot(&slot)
        .expect_err("an unhealthy resident slot must remain a visible calibration failure");
    assert!(error.contains("driver cleanup fault"));
    assert!(matches!(
        slot.into_inner().expect("unpoisoned slot"),
        GpuResidentLiteralSlot::Failed(reason) if reason == "driver cleanup fault"
    ));
}

/// Regression: WGPU adapters without both timestamp features must still return exact fused presence and positions through the untimed borrowed path.
#[test]
fn untimed_wgpu_adapter_uses_exact_borrowed_fused_scan() {
    let _gpu_test_guard = crate::testing::gpu_test_lock();
    let concrete_backend = match vyre_driver_wgpu::WgpuBackend::shared() {
        Ok(backend) => backend,
        Err(error) => {
            assert!(
                !crate::hw_probe::probe_hardware().gpu_available,
                "GPU hardware is present but the WGPU untimed fused test could not acquire it: {error}"
            );
            return;
        }
    };
    let backend: std::sync::Arc<dyn vyre::VyreBackend> = concrete_backend;
    let matcher = vyre_libs::scan::GpuLiteralSet::compile(&[b"a".as_slice()]);
    let slot = std::sync::Mutex::new(GpuResidentLiteralSlot::Empty);
    let mut consumed = None;

    scan_gpu_literal_evidence_by_region_resident(
        &slot,
        &matcher,
        &backend,
        false,
        b"zaa",
        &[0],
        |presence, matches| {
            let mut exact_matches = matches
                .iter()
                .map(|entry| (entry.pattern_id, entry.start, entry.end))
                .collect::<Vec<_>>();
            exact_matches.sort_unstable();
            consumed = Some((presence.to_vec(), exact_matches));
            Ok(())
        },
    )
    .expect("untimed WGPU fused scan must preserve complete evidence");

    assert_eq!(
        consumed,
        Some((vec![1], vec![(0, 1, 2), (0, 2, 3)])),
        "the untimed path must return the exact presence bit and byte ranges"
    );
    let state_guard = slot.lock().expect("untimed slot remains healthy");
    let GpuResidentLiteralSlot::Borrowed(state) = &*state_guard else {
        panic!("an adapter without timestamp support must retain borrowed scratch state")
    };
    assert!(state.output.is_empty());
    assert!(state.matches.is_empty());
    assert!(state.scratch.haystack_bytes.iter().all(|byte| *byte == 0));
    drop(state_guard);
    reset_resident_literal_slot(&slot).expect("untimed borrowed scratch resets cleanly");
}

/// Regression: fused literal overflow must replay once at the exact count on timed and untimed WGPU adapters.
#[test]
fn fused_match_overflow_replays_once_with_the_exact_device_count() {
    let _gpu_test_guard = crate::testing::gpu_test_lock();
    let concrete_backend = match vyre_driver_wgpu::WgpuBackend::shared() {
        Ok(backend) => backend,
        Err(error) => {
            assert!(
                !crate::hw_probe::probe_hardware().gpu_available,
                "GPU hardware is present but the WGPU fused overflow test could not acquire it: {error}"
            );
            return;
        }
    };
    let resident_timed_dispatch_supported = concrete_backend.device_queue().0.features().contains(
        wgpu::Features::TIMESTAMP_QUERY | wgpu::Features::TIMESTAMP_QUERY_INSIDE_ENCODERS,
    );
    let backend: std::sync::Arc<dyn vyre::VyreBackend> = concrete_backend;
    let matcher = vyre_libs::scan::GpuLiteralSet::compile(&[b"a".as_slice(), b"aa".as_slice()]);
    let slot = std::sync::Mutex::new(GpuResidentLiteralSlot::Empty);
    let haystack = vec![b'a'; super::GPU_FUSED_MATCH_CAP as usize];
    let mut consumed = None;

    scan_gpu_literal_evidence_by_region_resident(
        &slot,
        &matcher,
        &backend,
        resident_timed_dispatch_supported,
        &haystack,
        &[0],
        |presence, matches| {
            consumed = Some((presence.to_vec(), matches.len()));
            Ok(())
        },
    )
    .expect("dense positioned output must resize and replay completely");

    let (presence, matches) = consumed.expect("consumer runs exactly after the complete replay");
    assert_eq!(presence, vec![0b11]);
    assert_eq!(
        matches,
        haystack.len() * 2 - 1,
        "the replay returns every `a` and overlapping `aa` position"
    );
    let state_guard = slot.lock().expect("resident slot remains healthy");
    match &*state_guard {
        GpuResidentLiteralSlot::Ready(state) => {
            assert!(resident_timed_dispatch_supported);
            assert_eq!(state.pipeline.max_matches() as usize, matches);
        }
        GpuResidentLiteralSlot::Borrowed(state) => {
            assert!(!resident_timed_dispatch_supported);
            assert_eq!(state.max_matches as usize, matches);
        }
        GpuResidentLiteralSlot::Empty | GpuResidentLiteralSlot::Failed(_) => {
            panic!("overflow replay must retain a healthy timed or untimed pipeline")
        }
    }
    drop(state_guard);
    reset_resident_literal_slot(&slot).expect("resized resident resources free cleanly");

    let hostile = vec![b'a'; super::GPU_FUSED_MATCH_REPLAY_CAP as usize / 2 + 1];
    let mut consumed_hostile = false;
    let error = scan_gpu_literal_evidence_by_region_resident(
        &slot,
        &matcher,
        &backend,
        resident_timed_dispatch_supported,
        &hostile,
        &[0],
        |_presence, _matches| {
            consumed_hostile = true;
            Ok(())
        },
    )
    .expect_err("hostile density must not allocate beyond the replay budget");
    assert!(
        error.contains("exact GPU match count 2097153")
            && error.contains("bounded dense-replay cap 2097152"),
        "unexpected bounded replay error: {error}"
    );
    assert!(
        !consumed_hostile,
        "bounded overflow cannot expose partial evidence"
    );
    reset_resident_literal_slot(&slot).expect("bounded overflow leaves resident cleanup healthy");
}

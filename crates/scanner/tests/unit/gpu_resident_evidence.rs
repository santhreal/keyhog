use super::{
    finish_gpu_literal_evidence_by_region_resident, reset_resident_literal_slot,
    scan_gpu_literal_evidence_by_region_resident, submit_gpu_literal_evidence_by_region_resident,
    with_test_resident_dispatch_failure, GpuResidentLiteralSlot, GpuResidentPipelineConfig,
    ResidentLiteralCapacity, GPU_FUSED_MATCH_REPLAY_CAP,
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
#[test]
fn issue32_pipeline_depth_divides_one_process_budget_before_allocation() {
    let input_budget = crate::gpu_input_budget::gpu_batch_input_limit();
    for depth in 1..=4 {
        let config =
            GpuResidentPipelineConfig::for_depth(depth).expect("depth in calibrated range");
        assert_eq!(config.depth, depth);
        assert!(
            config.slot_input_capacity_bytes * usize::from(depth) <= input_budget,
            "depth {depth} multiplied the process GPU input budget"
        );
        assert!(
            config.slot_match_capacity * u32::from(depth) <= GPU_FUSED_MATCH_REPLAY_CAP,
            "depth {depth} multiplied the fused replay ceiling"
        );
    }
    assert!(GpuResidentPipelineConfig::for_depth(0).is_err());
    assert!(GpuResidentPipelineConfig::for_depth(5).is_err());
}

/// WHY: ring depth must divide every mutable resident allocation, including
/// detector-dependent presence rows. This does not cover immutable matcher tables.
#[test]
fn issue32_resident_capacity_counts_presence_storage_before_allocation() {
    let input_budget = u64::try_from(crate::gpu_input_budget::gpu_batch_input_limit())
        .expect("GPU input budget fits u64");
    let replay_budget = u64::from(GPU_FUSED_MATCH_REPLAY_CAP) * 12;
    let aggregate_ceiling = input_budget * 2 + replay_budget;

    for depth in 1..=4 {
        let base = ResidentLiteralCapacity::for_batch(4, 1, 1, depth)
            .expect("one presence word fits every supported ring depth");
        let per_slot = base
            .mutable_device_bytes()
            .expect("base resident byte accounting fits u64");
        let expected = 4 + 4 + 4 + 12 + u64::from(super::GPU_FUSED_MATCH_CAP) * 12;
        assert_eq!(per_slot, expected);
        assert!(
            per_slot * u64::from(depth) <= aggregate_ceiling,
            "depth {depth} must remain within the process ceiling"
        );

        let words_beyond_ceiling = usize::try_from(aggregate_ceiling / (u64::from(depth) * 4) + 1)
            .expect("test presence word count fits usize");
        let error = ResidentLiteralCapacity::for_batch(4, 1, words_beyond_ceiling, depth)
            .expect_err("presence storage alone cannot exceed the aggregate resident ceiling");
        assert!(
            error.contains("aggregate ceiling"),
            "unexpected depth-{depth} resident-capacity error: {error}"
        );
    }
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
    let matcher = vyre::scan::GpuLiteralSet::compile(&[b"a".as_slice()]);
    let slot = std::sync::Mutex::new(GpuResidentLiteralSlot::Empty);
    let mut consumed = None;

    scan_gpu_literal_evidence_by_region_resident(
        &slot,
        &matcher,
        &backend,
        false,
        b"zaa",
        &[0],
        1,
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

/// Regression: untimed adapters must expose injected dispatch failures to the same typed recovery boundary as timed resident adapters.
#[test]
fn untimed_borrowed_dispatch_exposes_injected_faults() {
    let _gpu_test_guard = crate::testing::gpu_test_lock();
    let concrete_backend = match vyre_driver_wgpu::WgpuBackend::shared() {
        Ok(backend) => backend,
        Err(error) => {
            assert!(
                !crate::hw_probe::probe_hardware().gpu_available,
                "GPU hardware is present but the WGPU untimed recovery test could not acquire it: {error}"
            );
            return;
        }
    };
    let backend: std::sync::Arc<dyn vyre::VyreBackend> = concrete_backend;
    let matcher = vyre::scan::GpuLiteralSet::compile(&[b"a".as_slice()]);
    let slot = std::sync::Mutex::new(GpuResidentLiteralSlot::Empty);

    let error = with_test_resident_dispatch_failure(0, || {
        scan_gpu_literal_evidence_by_region_resident(
            &slot,
            &matcher,
            &backend,
            false,
            b"zaa",
            &[0],
            1,
            |_, _| Ok(()),
        )
    })
    .expect_err("the untimed borrowed dispatch must surface its injected fault");

    assert_eq!(error, "injected borrowed fused literal dispatch fault");
    assert!(matches!(
        slot.into_inner().expect("untimed slot remains unpoisoned"),
        GpuResidentLiteralSlot::Empty
    ));
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
    let matcher = vyre::scan::GpuLiteralSet::compile(&[b"a".as_slice(), b"aa".as_slice()]);
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
        1,
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
            assert_eq!(
                state.sessions[0]
                    .pipeline
                    .as_ref()
                    .expect("resident replay retains its pipeline")
                    .max_matches() as usize,
                matches
            );
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
        1,
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

#[test]
fn issue32_async_slot_dense_overflow_replays_and_clears_owned_buffers() {
    let _gpu_test_guard = crate::testing::gpu_test_lock();
    let concrete_backend = match vyre_driver_wgpu::WgpuBackend::shared() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("skipping resident dense replay without WGPU: {error}");
            return;
        }
    };
    let backend: std::sync::Arc<dyn vyre::VyreBackend> = concrete_backend;
    let matcher = vyre::scan::GpuLiteralSet::compile(&[b"a".as_slice(), b"aa".as_slice()]);
    let slot = std::sync::Mutex::new(GpuResidentLiteralSlot::Empty);
    let haystack = vec![b'a'; super::GPU_FUSED_MATCH_CAP as usize];
    let pending = submit_gpu_literal_evidence_by_region_resident(
        &slot,
        &matcher,
        &backend,
        &haystack,
        &[0],
        1,
        2,
    )
    .expect("dense async slot submits at calibrated depth two");
    let count =
        finish_gpu_literal_evidence_by_region_resident(pending, &backend, |_presence, matches| {
            Ok(matches.len())
        })
        .expect("overflowed async slot replays at the exact count");
    assert_eq!(count, haystack.len() * 2 - 1);
    let guard = slot.lock().expect("resident slot remains healthy");
    let GpuResidentLiteralSlot::Ready(state) = &*guard else {
        panic!("dense replay must retain resident state")
    };
    let session = &state.sessions[0];
    assert!(!session.in_flight);
    assert!(session.input.is_empty());
    assert!(session.region_starts.is_empty());
    assert!(session.output.is_empty());
    assert!(session.matches.is_empty());
    assert!(session.scratch.iter().all(|byte| *byte == 0));
}

#[test]
fn issue32_abandoned_and_unwound_async_slots_retire_and_clear_before_reuse() {
    let _gpu_test_guard = crate::testing::gpu_test_lock();
    let concrete_backend = match vyre_driver_wgpu::WgpuBackend::shared() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("skipping resident cancellation cleanup without WGPU: {error}");
            return;
        }
    };
    let backend: std::sync::Arc<dyn vyre::VyreBackend> = concrete_backend;
    let matcher = vyre::scan::GpuLiteralSet::compile(&[b"token".as_slice()]);
    let slot = std::sync::Mutex::new(GpuResidentLiteralSlot::Empty);

    let pending = submit_gpu_literal_evidence_by_region_resident(
        &slot,
        &matcher,
        &backend,
        b"secret-token",
        &[0],
        1,
        4,
    )
    .expect("cancellation fixture submits");
    drop(pending);
    {
        let guard = slot.lock().expect("slot survives cancellation");
        let GpuResidentLiteralSlot::Ready(state) = &*guard else {
            panic!("cancelled pending work retains healthy resident state")
        };
        let session = &state.sessions[0];
        assert!(!session.in_flight);
        assert!(session.input.is_empty());
        assert!(session.region_starts.is_empty());
        assert!(session.output.is_empty());
        assert!(session.matches.is_empty());
        assert!(session.scratch.iter().all(|byte| *byte == 0));
    }

    let pending = submit_gpu_literal_evidence_by_region_resident(
        &slot,
        &matcher,
        &backend,
        b"another-token",
        &[0],
        1,
        4,
    )
    .expect("retired slot is reusable");
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = finish_gpu_literal_evidence_by_region_resident(
            pending,
            &backend,
            |_presence, _matches| -> Result<(), String> { panic!("injected consumer unwind") },
        );
    }));
    assert!(panic.is_err(), "consumer panic fixture must unwind");
    let guard = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let GpuResidentLiteralSlot::Ready(state) = &*guard else {
        panic!("unwound consumer retains healthy resident state")
    };
    assert!(state.sessions.iter().all(|session| {
        !session.in_flight
            && session.input.is_empty()
            && session.region_starts.is_empty()
            && session.output.is_empty()
            && session.matches.is_empty()
            && session.scratch.iter().all(|byte| *byte == 0)
    }));
}

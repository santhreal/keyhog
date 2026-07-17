use super::{
    reset_resident_literal_slot, scan_gpu_literal_evidence_by_region_resident,
    GpuResidentLiteralSlot,
};

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
fn fused_match_overflow_replays_once_with_the_exact_device_count() {
    let backend: std::sync::Arc<dyn vyre::VyreBackend> = match vyre_driver_wgpu::WgpuBackend::shared(
    ) {
        Ok(backend) => backend,
        Err(error) => {
            assert!(
                    !crate::hw_probe::probe_hardware().gpu_available,
                    "GPU hardware is present but the WGPU fused overflow test could not acquire it: {error}"
                );
            return;
        }
    };
    let matcher = vyre_libs::scan::GpuLiteralSet::compile(&[b"a".as_slice(), b"aa".as_slice()]);
    let slot = std::sync::Mutex::new(GpuResidentLiteralSlot::Empty);
    let haystack = vec![b'a'; super::GPU_FUSED_MATCH_CAP as usize];
    let mut consumed = None;

    scan_gpu_literal_evidence_by_region_resident(
        &slot,
        &matcher,
        &backend,
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
    let GpuResidentLiteralSlot::Ready(state) = &*state_guard else {
        panic!("overflow replay must retain a ready resident pipeline");
    };
    assert_eq!(state.pipeline.max_matches() as usize, matches);
    drop(state_guard);
    reset_resident_literal_slot(&slot).expect("resized resident resources free cleanly");

    let hostile = vec![b'a'; super::GPU_FUSED_MATCH_REPLAY_CAP as usize / 2 + 1];
    let mut consumed_hostile = false;
    let error = scan_gpu_literal_evidence_by_region_resident(
        &slot,
        &matcher,
        &backend,
        &hostile,
        &[0],
        |_presence, _matches| {
            consumed_hostile = true;
            Ok(())
        },
    )
    .expect_err("hostile density must not allocate beyond the replay budget");
    assert!(
        error.contains("exact GPU match count 1048577")
            && error.contains("bounded dense-replay cap 1048576"),
        "unexpected bounded replay error: {error}"
    );
    assert!(
        !consumed_hostile,
        "bounded overflow cannot expose partial evidence"
    );
    reset_resident_literal_slot(&slot).expect("bounded overflow leaves resident cleanup healthy");
}

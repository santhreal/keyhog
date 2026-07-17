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
fn fused_match_overflow_never_exposes_partial_evidence() {
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
    let mut consumed = false;

    let error = scan_gpu_literal_evidence_by_region_resident(
        &slot,
        &matcher,
        &backend,
        &haystack,
        &[0],
        |_presence, _matches| {
            consumed = true;
            Ok(())
        },
    )
    .expect_err("dense positioned output must exceed the resident match budget");

    assert!(
        error.contains("exceeds the output-buffer cap"),
        "unexpected overflow error: {error}"
    );
    assert!(
        !consumed,
        "the consumer must never observe presence or positions from an overflowed fused dispatch"
    );
    reset_resident_literal_slot(&slot).expect("overflow does not poison resident cleanup");
}

use keyhog::testing::{CliTestApi, API};

#[test]
fn automatic_gpu_failure_replays_the_stable_batch_without_losing_bytes() {
    let guard = API.scan_runtime_guard_for_test();
    let body = "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n";

    let detector_ids = API
        .disabled_gpu_dispatch_for_test(body, true, &guard)
        .expect("automatic GPU recovery should complete the stable input on CPU");
    let snapshot = API.scan_runtime_snapshot(&guard);

    assert_eq!(
        detector_ids
            .iter()
            .filter(|detector_id| detector_id.as_str() == "aws-access-key")
            .count(),
        1,
        "the exact planted detector must survive recovery once: {detector_ids:?}"
    );
    assert_eq!(snapshot.backend_recovery_events, 1);
    assert_eq!(snapshot.backend_recovered_chunks, 1);
    assert_eq!(snapshot.backend_recovered_bytes, body.len() as u64);
    assert_eq!(snapshot.gpu_scanned_chunks, 0);
    assert_eq!(snapshot.source_errors, 0);
    assert_eq!(snapshot.failed_sources, 0);
}

#[test]
fn selected_gpu_failure_is_hard_when_recovery_is_not_allowed() {
    let guard = API.scan_runtime_guard_for_test();
    let body = "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n";

    let error = API
        .disabled_gpu_dispatch_for_test(body, false, &guard)
        .expect_err("a selected GPU contract must not substitute CPU");
    assert!(
        error.to_string().contains("GPU scanner failure"),
        "operator must see the selected GPU failure: {error:#}"
    );
    let snapshot = API.scan_runtime_snapshot(&guard);
    assert_eq!(snapshot.backend_recovery_events, 0);
    assert_eq!(snapshot.backend_recovered_chunks, 0);
    assert_eq!(snapshot.backend_recovered_bytes, 0);
}

#[test]
fn recovery_is_reserved_for_unforced_production_autoroute() {
    use keyhog_scanner::{gpu::GpuRuntimePolicy, ScanBackend};

    assert!(API.automatic_gpu_recovery_allowed_for_test(None, false, GpuRuntimePolicy::Auto));
    assert!(!API.automatic_gpu_recovery_allowed_for_test(None, false, GpuRuntimePolicy::Required));
    assert!(!API.automatic_gpu_recovery_allowed_for_test(None, false, GpuRuntimePolicy::Disabled));
    assert!(!API.automatic_gpu_recovery_allowed_for_test(
        Some(ScanBackend::GpuWgpu),
        false,
        GpuRuntimePolicy::Auto
    ));
    assert!(!API.automatic_gpu_recovery_allowed_for_test(None, true, GpuRuntimePolicy::Auto));
}

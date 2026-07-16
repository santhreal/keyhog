use keyhog::testing::{CliTestApi, API};

#[test]
fn automatic_gpu_failure_replays_the_stable_batch_without_losing_bytes() {
    let guard = API.scan_runtime_guard_for_test();
    let body = "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n";

    let detector_ids = API
        .recover_disabled_gpu_batch_for_test(body, &guard)
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

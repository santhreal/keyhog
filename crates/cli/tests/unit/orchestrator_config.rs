use keyhog::orchestrator_config::{sanitise_thread_count_for_test as sanitise, MAX_THREADS_CAP};

#[test]
fn sanitise_thread_count_rejects_zero() {
    assert_eq!(sanitise(0, 8, "test"), 8);
    assert_eq!(sanitise(0, 0, "test"), 1);
}

#[test]
fn sanitise_thread_count_caps_pathological_values() {
    assert_eq!(sanitise(999_999, 8, "test"), MAX_THREADS_CAP);
    assert_eq!(sanitise(MAX_THREADS_CAP + 1, 8, "test"), MAX_THREADS_CAP);
}

#[test]
fn sanitise_thread_count_passes_through_sane_values() {
    assert_eq!(sanitise(1, 8, "test"), 1);
    assert_eq!(sanitise(8, 8, "test"), 8);
    assert_eq!(sanitise(64, 8, "test"), 64);
    assert_eq!(sanitise(MAX_THREADS_CAP, 8, "test"), MAX_THREADS_CAP);
}

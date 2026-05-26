use keyhog::orchestrator_config::sanitise_thread_count_for_test;

#[test]
fn sanitise_thread_count_caps_pathological() {
    assert_eq!(sanitise_thread_count_for_test(999_999, 8, "test"), 256);
}

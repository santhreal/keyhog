use keyhog::orchestrator_config::sanitise_thread_count_for_test;

#[test]
fn sanitise_thread_count_zero_fallback() {
    assert_eq!(sanitise_thread_count_for_test(0, 8, "test"), 8);
}

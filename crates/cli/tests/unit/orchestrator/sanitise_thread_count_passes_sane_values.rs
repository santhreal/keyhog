use keyhog::orchestrator_config::sanitise_thread_count_for_test;

#[test]
fn sanitise_thread_count_passes_sane_values() {
    assert_eq!(sanitise_thread_count_for_test(4, 8, "test"), 4);
}

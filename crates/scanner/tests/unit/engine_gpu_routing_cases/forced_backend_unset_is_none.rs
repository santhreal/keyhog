use keyhog_scanner::hw_probe::testing::forced_backend_override_for_test;
use keyhog_scanner::testing::clear_test_backend_override;
#[test]
fn forced_backend_unset_is_none() {
    clear_test_backend_override();
    assert!(forced_backend_override_for_test().is_none());
}

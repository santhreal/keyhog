use keyhog_scanner::hw_probe::testing::probe_hardware;
#[test]
fn probe_hardware_is_cached() {
    assert!(std::ptr::eq(probe_hardware(), probe_hardware()));
}

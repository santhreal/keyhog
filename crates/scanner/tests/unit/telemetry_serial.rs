#[must_use = "hold the scanner telemetry serial lock while touching process-global telemetry"]
pub(super) fn lock() -> std::sync::MutexGuard<'static, ()> {
    keyhog_scanner::testing::telemetry_serial_lock()
}

#[test]
fn telemetry_serial_lock_recovers_from_poisoned_test_lock() {
    let joined = std::thread::spawn(|| {
        let _guard = lock();
        panic!("poison scanner telemetry serial test lock");
    })
    .join();
    assert!(
        joined.is_err(),
        "poisoning setup should panic inside thread"
    );

    let _guard = lock();
    keyhog_scanner::telemetry::testing::reset();
    assert!(keyhog_scanner::telemetry::drain_events().is_empty());
}

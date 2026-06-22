pub(super) fn lock() -> std::sync::MutexGuard<'static, ()> {
    keyhog_scanner::testing::telemetry_serial_lock()
}

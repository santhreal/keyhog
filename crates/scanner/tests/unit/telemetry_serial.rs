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

/// `reset_for_scan` is the single per-scan reset owner. It must zero EVERY
/// coverage-gap counter — the historical bug omitted `STRUCTURED_OVERSIZE_SKIPS`
/// so an oversize-skip count leaked into the next scan's report. Driving the reset
/// through `ScannerCoverageGapEvent::ALL` makes forgetting a counter impossible.
/// Migrated from an inline `mod reset_owner_tests` (per-scan counters are
/// process-global, so it holds the telemetry serial lock).
#[test]
fn reset_for_scan_zeroes_every_coverage_gap_counter() {
    let _guard = lock();
    assert!(
        keyhog_scanner::testing::telemetry_reset_zeroes_all_seeded_gap_counters(),
        "reset_for_scan must zero every coverage-gap counter"
    );
}

/// `ALL` must list every variant, or the reset owner would skip whatever is
/// missing. Guards against a new variant being added without extending `ALL`.
#[test]
fn coverage_gap_event_all_covers_every_variant() {
    let (len, all_present) = keyhog_scanner::testing::telemetry_coverage_gap_all_completeness();
    assert_eq!(
        len, 6,
        "ScannerCoverageGapEvent::ALL must list all 6 variants"
    );
    assert!(
        all_present,
        "ScannerCoverageGapEvent::ALL is missing a variant"
    );
}

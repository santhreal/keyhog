//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::Calibration;
#[test]
    fn record_methods_saturate_at_u32_max() {
        let c = Calibration::empty();
        // Seed the counters near saturation by manipulating the inner
        // map directly. Production paths never need to do this; it's a
        // test backdoor to prove the saturating_add contract.
        {
            let mut guard = c.inner.write();
            guard.entry("saturating".to_string()).or_default().alpha = u32::MAX;
            guard.entry("saturating".to_string()).or_default().beta = u32::MAX;
        }
        // Both increments must NOT panic in debug and NOT wrap to 0.
        c.record_true_positive("saturating");
        c.record_false_positive("saturating");
        let counters = c.counters("saturating");
        assert_eq!(counters.alpha, u32::MAX, "alpha must saturate at u32::MAX");
        assert_eq!(counters.beta, u32::MAX, "beta must saturate at u32::MAX");
        // observations() also uses saturating_add internally — the sum
        // of two saturated values clamps at u32::MAX rather than
        // panicking or wrapping.
        assert_eq!(counters.observations(), u32::MAX);
    }

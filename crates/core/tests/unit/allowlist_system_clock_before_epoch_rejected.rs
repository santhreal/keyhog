//! Broken host clocks must not make expired allowlist entries active.

use std::time::{Duration, UNIX_EPOCH};

use keyhog_core::testing::{CoreTestApi, TestApi};

#[test]
fn allowlist_clock_before_epoch_is_error() {
    let error = TestApi
        .allowlist_days_since_epoch_for_test(UNIX_EPOCH - Duration::from_secs(1))
        .expect_err("pre-epoch host clocks cannot support allowlist expiry");

    assert!(
        error.contains("system clock is before UNIX_EPOCH")
            && error.contains("fix host time before loading allowlist suppressions"),
        "clock error must be actionable; got: {error}"
    );
}

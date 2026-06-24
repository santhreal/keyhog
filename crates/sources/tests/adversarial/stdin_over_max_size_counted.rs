//! Oversized stdin must fail loud and increment size-limit telemetry.

use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};

#[test]
fn stdin_over_max_size_counted() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let err = TestApi
        .read_stdin_test_input_with_limit(b"abcd", 3)
        .expect_err("stdin above configured cap must fail loud");

    assert!(
        err.to_string().contains("stdin exceeds 3 byte limit"),
        "expected stdin cap error, got {err:?}"
    );
    let counts = skip_counts();
    assert_eq!(
        counts.over_max_size, 1,
        "oversized stdin must be counted as an over-max-size coverage gap"
    );
    assert_eq!(
        counts.unreadable, 0,
        "oversized stdin is a size policy failure, not unreadable input"
    );
}

#[test]
fn stdin_at_max_size_is_not_counted_as_skipped() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let text = TestApi
        .read_stdin_test_input_with_limit(b"abc", 3)
        .expect("stdin at the exact configured cap must be accepted");

    assert_eq!(text, "abc");
    assert_eq!(
        skip_counts().over_max_size,
        0,
        "stdin exactly at cap must not increment skip telemetry"
    );
}

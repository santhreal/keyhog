use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sigv4_timestamp_hour_boundary_23_59_to_00_00() {
    // 2024-01-01 23:59:00 UTC
    let unix_secs = 1_704_153_540u64;
    let (d, a) = TestApi.format_sigv4_timestamps(unix_secs);
    assert_eq!(d, "20240101", "date_stamp must remain same day");
    assert_eq!(a, "20240101T235900Z", "amz_date hour must be 23");

    // 2024-01-02 00:00:00 UTC (exactly 60 seconds later)
    let unix_secs = 1_704_153_600u64;
    let (d, a) = TestApi.format_sigv4_timestamps(unix_secs);
    assert_eq!(d, "20240102", "date_stamp must roll to next day");
    assert_eq!(a, "20240102T000000Z", "amz_date must be midnight");
}

#[test]
fn sigv4_timestamp_minute_boundary_59_to_00() {
    // 2024-01-01 12:59:00 UTC
    let unix_secs = 1_704_113_940u64;
    let (d, a) = TestApi.format_sigv4_timestamps(unix_secs);
    assert_eq!(d, "20240101", "date_stamp unchanged");
    assert_eq!(a, "20240101T125900Z", "amz_date minute must be 59");

    // 2024-01-01 13:00:00 UTC (exactly 60 seconds later)
    let unix_secs = 1_704_114_000u64;
    let (d, a) = TestApi.format_sigv4_timestamps(unix_secs);
    assert_eq!(d, "20240101", "date_stamp unchanged");
    assert_eq!(a, "20240101T130000Z", "amz_date minute must roll to 00");
}

#[test]
fn sigv4_timestamp_second_boundary_59_to_00() {
    // 2024-01-01 12:34:59 UTC
    let unix_secs = 1_704_112_499u64;
    let (d, a) = TestApi.format_sigv4_timestamps(unix_secs);
    assert_eq!(d, "20240101", "date_stamp unchanged");
    assert_eq!(a, "20240101T123459Z", "amz_date second must be 59");

    // 2024-01-01 12:35:00 UTC (exactly 1 second later)
    let unix_secs = 1_704_112_500u64;
    let (d, a) = TestApi.format_sigv4_timestamps(unix_secs);
    assert_eq!(d, "20240101", "date_stamp unchanged");
    assert_eq!(a, "20240101T123500Z", "amz_date second must roll to 00");
}

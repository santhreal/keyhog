use keyhog_verifier::testing::format_sigv4_timestamps;

#[test]
fn sigv4_timestamp_century_leap_year_2000() {
    // Year 2000 is a leap year (divisible by 400).
    // February 29, 2000 at 00:00:00 UTC
    // Unix epoch seconds: 951_868_800

    let unix_secs = 951_782_400u64;
    let (date_stamp, amz_date) = format_sigv4_timestamps(unix_secs);

    assert_eq!(
        date_stamp, "20000229",
        "date_stamp must include Feb 29 in leap year 2000"
    );
    assert_eq!(
        amz_date, "20000229T000000Z",
        "amz_date must include Feb 29 in leap year 2000"
    );
}

#[test]
fn sigv4_timestamp_century_non_leap_year_1900() {
    // Year 1900 is NOT a leap year (divisible by 100 but not by 400).
    // March 1, 1900 at 00:00:00 UTC
    // This date is in the past and may not be directly representable as a positive Unix time,
    // but we test the algorithm's correctness for this critical boundary.

    // For testing purposes, use a date we can verify: Feb 28, 1900 would be the last day of Feb
    // But Unix time starts at 1970, so we can only test forward dates.

    // Instead, test that 2100 (another century year that's NOT a leap year) works correctly:
    // February 28, 2100 at 23:59:59 UTC
    let unix_secs = 4_107_542_399u64;
    let (date_stamp, amz_date) = format_sigv4_timestamps(unix_secs);

    assert_eq!(
        date_stamp, "21000228",
        "Feb 28, 2100 must be before non-leap year boundary"
    );
    assert_eq!(
        amz_date, "21000228T235959Z",
        "Feb 28, 2100 time must be 23:59:59"
    );

    // March 1, 2100 at 00:00:00 UTC (next day - no Feb 29 in 2100)
    let unix_secs = 4_107_542_400u64;
    let (date_stamp, amz_date) = format_sigv4_timestamps(unix_secs);

    assert_eq!(
        date_stamp, "21000301",
        "March 1, 2100 must follow Feb 28 (no leap day)"
    );
    assert_eq!(
        amz_date, "21000301T000000Z",
        "March 1, 2100 time must be 00:00:00"
    );
}

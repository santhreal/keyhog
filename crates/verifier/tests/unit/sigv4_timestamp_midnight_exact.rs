use keyhog_verifier::testing::format_sigv4_timestamps;

#[test]
fn sigv4_timestamp_midnight_exact_boundaries() {
    // This test verifies that exact midnight transitions (00:00:00)
    // produce the correct date_stamp, which is critical for AWS SigV4
    // signature calculation. A single-second error here breaks the signature.

    // Test multiple midnight transitions to ensure consistency
    let midnight_dates = vec![
        // Unix timestamp, expected date_stamp, expected amz_date
        (0u64, "19700101", "19700101T000000Z"), // Jan 1, 1970 midnight
        (86_400u64, "19700102", "19700102T000000Z"), // Jan 2, 1970 midnight
        (1_704_067_200u64, "20240101", "20240101T000000Z"), // Jan 1, 2024 midnight
        (1_709_251_200u64, "20240301", "20240301T000000Z"), // Mar 1, 2024 midnight
    ];

    for (unix_secs, expected_d, expected_a) in midnight_dates {
        let (d, a) = format_sigv4_timestamps(unix_secs);
        assert_eq!(
            d, expected_d,
            "midnight date_stamp at unix_secs={} must be exact",
            unix_secs
        );
        assert_eq!(
            a, expected_a,
            "midnight amz_date at unix_secs={} must be exact",
            unix_secs
        );
        // Verify the time component is exactly 000000
        assert_eq!(
            &a[9..15],
            "000000",
            "midnight must have time=000000 at unix_secs={}",
            unix_secs
        );
    }
}

#[test]
fn sigv4_timestamp_one_second_before_midnight() {
    // Critical boundary: the second before midnight must show the CURRENT day,
    // not the next day. This is essential for AWS SigV4 canonical request construction.

    // Dec 31, 2023 at 23:59:59 UTC
    let unix_secs = 1_704_067_199u64;
    let (d, a) = format_sigv4_timestamps(unix_secs);

    assert_eq!(
        d, "20231231",
        "one second before midnight must show current day"
    );
    assert_eq!(
        a, "20231231T235959Z",
        "one second before midnight shows 23:59:59"
    );
    assert!(a.ends_with("235959Z"), "seconds must be 59");
}

#[test]
fn sigv4_timestamp_one_second_after_midnight() {
    // One second after midnight must show the NEXT day.

    // Jan 1, 2024 at 00:00:01 UTC
    let unix_secs = 1_704_067_201u64;
    let (d, a) = format_sigv4_timestamps(unix_secs);

    assert_eq!(d, "20240101", "one second after midnight shows next day");
    assert_eq!(
        a, "20240101T000001Z",
        "one second after midnight shows 00:00:01"
    );
}

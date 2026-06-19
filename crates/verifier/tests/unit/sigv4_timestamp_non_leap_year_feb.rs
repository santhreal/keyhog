use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sigv4_timestamp_non_leap_year_feb_28_2023() {
    // 2023-02-28 00:00:00 (non-leap year Feb 28)
    // Feb 28, 2023 at 00:00 UTC
    let unix_secs = 1_677_542_400u64;
    let (d, a) = TestApi.format_sigv4_timestamps(unix_secs);
    assert_eq!(d, "20230228", "date_stamp must be YYYYMMDD");
    assert_eq!(a, "20230228T000000Z", "amz_date must be YYYYMMDDTHHMMSSZ");
}

#[test]
fn sigv4_timestamp_non_leap_year_mar_1_2023() {
    // 2023-03-01 00:00:00 (next day after non-leap Feb 28)
    let unix_secs = 1_677_628_800u64;
    let (d, a) = TestApi.format_sigv4_timestamps(unix_secs);
    assert_eq!(d, "20230301", "date_stamp must be YYYYMMDD");
    assert_eq!(a, "20230301T000000Z", "amz_date must be YYYYMMDDTHHMMSSZ");
}

use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sigv4_timestamp_year_boundary_dec_31_2023() {
    // 2023-12-31 23:59:59 (last second of 2023)
    let unix_secs = 1_704_067_199u64;
    let (d, a) = TestApi.format_sigv4_timestamps(unix_secs);
    assert_eq!(d, "20231231", "date_stamp must be YYYYMMDD");
    assert_eq!(a, "20231231T235959Z", "amz_date must be YYYYMMDDTHHMMSSZ");
}

#[test]
fn sigv4_timestamp_year_boundary_jan_1_2024() {
    // 2024-01-01 00:00:00 (first second of 2024)
    let unix_secs = 1_704_067_200u64;
    let (d, a) = TestApi.format_sigv4_timestamps(unix_secs);
    assert_eq!(d, "20240101", "date_stamp must be YYYYMMDD");
    assert_eq!(a, "20240101T000000Z", "amz_date must be YYYYMMDDTHHMMSSZ");
}

use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sigv4_leap_year_feb_29() {
    let (d, a) = TestApi.format_sigv4_timestamps(1_709_210_096);
    assert_eq!(d, "20240229");
    assert_eq!(a, "20240229T123456Z");
}

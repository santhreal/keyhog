use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sigv4_known_aws_example() {
    let (d, a) = TestApi.format_sigv4_timestamps(1_704_067_200);
    assert_eq!(d, "20240101");
    assert_eq!(a, "20240101T000000Z");
}

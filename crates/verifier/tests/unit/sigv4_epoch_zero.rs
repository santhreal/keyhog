use keyhog_verifier::testing::format_sigv4_timestamps;

#[test]
fn sigv4_epoch_zero() {
    let (d, a) = format_sigv4_timestamps(0);
    assert_eq!(d, "19700101");
    assert_eq!(a, "19700101T000000Z");
}

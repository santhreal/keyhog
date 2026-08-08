use keyhog_verifier::testing::prewarm_oob_key_for_test;

/// WHY: OOB registration must consume a key generated concurrently with scanning,
/// while every registration retains an independent RSA-2048 session key.
#[test]
fn prewarmed_oob_keys_are_consumable_and_session_unique() {
    let (first_pending, first_modulus) =
        prewarm_oob_key_for_test().expect("first OOB key prewarm must succeed");
    let (second_pending, second_modulus) =
        prewarm_oob_key_for_test().expect("second OOB key prewarm must succeed");

    assert!(
        first_pending,
        "prewarm did not publish the first key handle"
    );
    assert!(
        second_pending,
        "prewarm did not publish the second key handle"
    );
    assert_eq!(first_modulus.len(), 256, "first key is not RSA-2048");
    assert_eq!(second_modulus.len(), 256, "second key is not RSA-2048");
    assert_ne!(
        first_modulus, second_modulus,
        "separate OOB registrations reused one RSA session key"
    );
}

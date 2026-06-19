//! UPPER EXAMPLE placeholder tokens are rejected by plausibility.

use keyhog_scanner::testing::entropy_keywords::is_secret_plausible;

#[test]
fn entropy_placeholder_upper_example() {
    assert!(
        !is_secret_plausible("YOUR_API_KEY_EXAMPLE", &[]),
        "EXAMPLE placeholder must fail strict plausibility"
    );
}

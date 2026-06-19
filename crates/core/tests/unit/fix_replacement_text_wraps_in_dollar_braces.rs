//! Migrated from `src/auto_fix.rs` inline tests.
#[test]
fn fix_replacement_text_wraps_in_dollar_braces() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_replacement_text(
            &keyhog_core::testing::TestApi,
            "aws"
        ),
        "${AWS_ACCESS_KEY_ID}"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_replacement_text(
            &keyhog_core::testing::TestApi,
            "acme-x"
        ),
        "${ACME_X_KEY}"
    );
}

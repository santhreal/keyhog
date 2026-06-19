//! Migrated from `src/auto_fix.rs` inline tests.
#[test]
fn fix_replacement_text_empty_service_still_wraps() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_replacement_text(
            &keyhog_core::testing::TestApi,
            ""
        ),
        "${_KEY}"
    );
}

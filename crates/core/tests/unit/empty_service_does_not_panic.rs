//! Migrated from `src/auto_fix.rs` inline tests.
#[test]
fn empty_service_does_not_panic() {
    // "" → trim_matches('_') yields "" → "" + "_KEY" = "_KEY"
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            ""
        ),
        "_KEY"
    );
}

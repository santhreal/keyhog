//! Migrated from `src/auto_fix.rs` inline tests.
#[test]
fn unknown_service_falls_back_to_screaming_snake() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "acme-widget-api"
        ),
        "ACME_WIDGET_API_KEY"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "RevenueCat"
        ),
        "REVENUECAT_KEY"
    );
}

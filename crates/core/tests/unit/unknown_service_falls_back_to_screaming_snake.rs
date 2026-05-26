//! Migrated from `src/auto_fix.rs` inline tests.
use keyhog_core::auto_fix::{env_var_name_for_service, fix_replacement_text};
#[test]
    fn unknown_service_falls_back_to_screaming_snake() {
        assert_eq!(
            env_var_name_for_service("acme-widget-api"),
            "ACME_WIDGET_API_KEY"
        );
        assert_eq!(env_var_name_for_service("RevenueCat"), "REVENUECAT_KEY");
    }

//! Migrated from `src/auto_fix.rs` inline tests.
use keyhog_core::{env_var_name_for_service, fix_replacement_text};
#[test]
    fn empty_service_does_not_panic() {
        // "" → trim_matches('_') yields "" → "" + "_KEY" = "_KEY"
        assert_eq!(env_var_name_for_service(""), "_KEY");
    }

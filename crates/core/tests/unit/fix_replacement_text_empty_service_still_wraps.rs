//! Migrated from `src/auto_fix.rs` inline tests.
use keyhog_core::{env_var_name_for_service, fix_replacement_text};
#[test]
    fn fix_replacement_text_empty_service_still_wraps() {
        assert_eq!(fix_replacement_text(""), "${_KEY}");
    }

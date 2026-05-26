//! Migrated from `src/auto_fix.rs` inline tests.
use keyhog_core::auto_fix::{env_var_name_for_service, fix_replacement_text};
#[test]
fn fix_replacement_text_wraps_in_dollar_braces() {
    assert_eq!(fix_replacement_text("aws"), "${AWS_ACCESS_KEY_ID}");
    assert_eq!(fix_replacement_text("acme-x"), "${ACME_X_KEY}");
}

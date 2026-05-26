//! Migrated from `src/auto_fix.rs` inline tests.
use keyhog_core::auto_fix::{env_var_name_for_service, fix_replacement_text};
#[test]
fn service_with_path_separators_normalizes_to_screaming_snake() {
    assert_eq!(
        env_var_name_for_service("../../etc/passwd"),
        "ETC_PASSWD_KEY"
    );
}

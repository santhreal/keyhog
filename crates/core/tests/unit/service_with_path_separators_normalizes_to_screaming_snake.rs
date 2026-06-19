//! Migrated from `src/auto_fix.rs` inline tests.
#[test]
fn service_with_path_separators_normalizes_to_screaming_snake() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "../../etc/passwd"
        ),
        "ETC_PASSWD_KEY"
    );
}

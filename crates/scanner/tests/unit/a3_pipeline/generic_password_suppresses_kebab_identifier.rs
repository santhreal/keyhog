use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::named_detector_suppressed;

#[test]
fn kebab_case_config_name_suppressed_for_generic_password() {
    // Dogfood: cobra/setting.go and golang config files match
    // `(?i)password[=:]<value>` regex and capture kebab-case field
    // names like `user-password`, `aria-secret`, `api-token`. These
    // are config keys, not credentials.
    assert!(named_detector_suppressed(
        "user-password",
        Some("config/setting.go"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
}

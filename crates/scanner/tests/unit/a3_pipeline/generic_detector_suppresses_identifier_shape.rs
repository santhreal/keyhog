use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_named_detector_finding;

#[test]
fn c_function_name_suppressed_for_generic_password() {
    assert!(should_suppress_named_detector_finding(
        "sk_SRP_user_pwd_new_null",
        Some("openssl/srp_vfy.c"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
}

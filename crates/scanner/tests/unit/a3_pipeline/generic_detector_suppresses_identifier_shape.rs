use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::named_detector_suppressed;

#[test]
fn c_function_name_suppressed_for_generic_password() {
    assert!(named_detector_suppressed(
        "sk_SRP_user_pwd_new_null",
        Some("openssl/srp_vfy.c"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
}

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn mixed_case_hex_not_hash_digest() {
    assert!(!should_suppress_known_example_credential(
        "AbCdEf0123456789AbCdEf0123456789",
        None,
        CodeContext::Unknown,
    ));
}

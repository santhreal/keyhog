use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn mixed_case_hex_not_hash_digest() {
    assert!(!known_example_suppressed(
        "AbCdEf0123456789AbCdEf0123456789",
        None,
        CodeContext::Unknown,
    ));
}

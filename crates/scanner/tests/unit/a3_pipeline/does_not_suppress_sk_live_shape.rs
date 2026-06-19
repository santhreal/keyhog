use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn sk_live_realistic_not_suppressed() {
    assert!(!should_suppress_known_example_credential(
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        None,
        CodeContext::Assignment,
    ));
}

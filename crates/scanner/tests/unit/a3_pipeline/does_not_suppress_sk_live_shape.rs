use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn sk_live_realistic_not_suppressed() {
    assert!(!known_example_suppressed(
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        None,
        CodeContext::Assignment,
    ));
}

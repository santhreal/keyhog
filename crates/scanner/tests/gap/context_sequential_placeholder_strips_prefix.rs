//! KH-GAP-018: sequential placeholder detection must strip known prefixes first.

use keyhog_scanner::context::is_known_example_credential;

#[test]
fn context_sequential_placeholder_strips_prefix() {
    assert!(
        is_known_example_credential("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "all-same-char body after ghp_ prefix must suppress as placeholder"
    );
}

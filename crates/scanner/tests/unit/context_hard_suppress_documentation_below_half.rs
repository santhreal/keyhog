//! Documentation context hard-suppresses confidence below 0.5.

use keyhog_scanner::context::CodeContext;

#[test]
fn context_hard_suppress_documentation_below_half() {
    assert!(
        CodeContext::Documentation.should_hard_suppress(0.49),
        "documentation with confidence 0.49 must hard-suppress"
    );
    assert!(
        !CodeContext::Documentation.should_hard_suppress(0.51),
        "documentation with confidence 0.51 must not hard-suppress"
    );
}

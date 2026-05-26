//! Assignment context never hard-suppresses regardless of confidence.

use keyhog_scanner::context::CodeContext;

#[test]
fn context_hard_suppress_assignment_never() {
    assert!(
        !CodeContext::Assignment.should_hard_suppress(0.01),
        "assignment context must never hard-suppress"
    );
}

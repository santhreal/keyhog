//! Encrypted context hard-suppresses below 0.8 confidence.

use keyhog_scanner::context::CodeContext;

#[test]
fn context_hard_suppress_encrypted_below_point_eight() {
    assert!(
        CodeContext::Encrypted.should_hard_suppress(0.79),
        "encrypted context confidence 0.79 must hard-suppress"
    );
    assert!(
        !CodeContext::Encrypted.should_hard_suppress(0.81),
        "encrypted context confidence 0.81 must not hard-suppress"
    );
}

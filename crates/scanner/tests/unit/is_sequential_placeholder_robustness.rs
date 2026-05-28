//! Robustness tests for sequential placeholder detection logic.

use keyhog_scanner::context::is_sequential_placeholder;

#[test]
fn test_is_sequential_placeholder_robustness() {
    // Verify that "ababababa" is correctly suppressed (returns true)
    assert!(
        is_sequential_placeholder("ababababa"),
        "ababababa must be suppressed as a sequential placeholder"
    );

    // Verify that "ababababx" is NOT suppressed (returns false)
    assert!(
        !is_sequential_placeholder("ababababx"),
        "ababababx must not be suppressed as a sequential placeholder"
    );

    // Verify longer instances of the same patterns
    assert!(
        is_sequential_placeholder("ababababababababa"),
        "longer odd-length sequential placeholder must be suppressed"
    );
    assert!(
        !is_sequential_placeholder("ababababababababx"),
        "longer non-sequential odd-length string must not be suppressed"
    );
}

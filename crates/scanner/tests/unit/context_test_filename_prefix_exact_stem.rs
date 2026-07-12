//! The `test_` filename-prefix rule uses `stem.len() >= prefix.len()`, not `>`.
//! A file whose stem IS the prefix exactly (`test_.py` -> stem `test_`) is still
//! a test file; the off-by-one `>` dropped that exact-equal boundary and left
//! the fixture at full confidence.

use keyhog_scanner::context::{infer_context, CodeContext};

/// A line that on its own infers to `Unknown`, so the ONLY thing that can make
/// these classify as `TestCode` is the filename-prefix rule under test.
const NEUTRAL_LINE: &str = "just_some_prose_here";

#[test]
fn test_underscore_stem_equal_to_prefix_is_test_file() {
    // stem `test_` == prefix `test_`: `5 >= 5` matches (the exact-equal case the
    // old `>` boundary wrongly excluded).
    let lines = vec![NEUTRAL_LINE];
    assert_eq!(
        infer_context(&lines, 0, Some("src/test_.py")),
        CodeContext::TestCode,
        "test_.py (stem == prefix exactly) must be TestCode"
    );
    // Ordinary longer prefix match still holds.
    assert_eq!(
        infer_context(&lines, 0, Some("src/test_utils.py")),
        CodeContext::TestCode,
        "test_utils.py must be TestCode"
    );
}

#[test]
fn shorter_or_non_underscore_prefix_is_not_a_test_file() {
    let lines = vec![NEUTRAL_LINE];
    // stem `test` (len 4) < prefix `test_` (len 5): the prefix requires the
    // trailing underscore, so a bare `test.py` is NOT a test file by this rule.
    assert_ne!(
        infer_context(&lines, 0, Some("src/test.py")),
        CodeContext::TestCode,
        "test.py is shorter than the test_ prefix and must not be TestCode"
    );
    // stem `testicular` shares the first four bytes `test` but byte 5 is `i`,
    // not `_`, so it must not match the `test_` prefix.
    assert_ne!(
        infer_context(&lines, 0, Some("src/testicular.py")),
        CodeContext::TestCode,
        "testicular.py does not carry the test_ prefix and must not be TestCode"
    );
}

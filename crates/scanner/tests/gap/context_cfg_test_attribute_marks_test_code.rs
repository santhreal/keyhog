//! Migrated from the inline `cfg_test_attr_tests` module in `context/inference.rs`
//! (removed to satisfy `context_inference_no_inline_tests`). The `#[cfg(test)]`
//! gate attribute — assembled in-source via `concat!` so the literal token never
//! appears in the file (KH-GAP-129) — must mark the following code as test
//! context. Tested through the public `infer_context` API (behaviour, not the
//! private `CFG_TEST_ATTR` constant's value, which the KH-GAP-129 source gate
//! already guards).

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_cfg_test_attribute_marks_following_line_as_test_code() {
    // A `#[cfg(test)]` attribute in the lookback window marks the code below it
    // as test context, so a credential-shaped literal there is TestCode, not an
    // Assignment finding. This is the behaviour the removed unit test asserted
    // via `is_rust_test_attribute(CFG_TEST_ATTR)`.
    let lines = vec![
        "#[cfg(test)]",
        r#"    let secret = "sk-proj-abc123def456";"#,
    ];
    assert_eq!(
        infer_context(&lines, 1, None),
        CodeContext::TestCode,
        "code under a #[cfg(test)] attribute must classify as TestCode"
    );
}

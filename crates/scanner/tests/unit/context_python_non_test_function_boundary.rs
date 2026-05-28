//! Non-test Python def stops test-function lookback.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_python_non_test_function_boundary() {
    let lines = vec!["def configure():", r#"    api_key = "sk-proj-production""#];
    assert_eq!(
        infer_context(&lines, 1, None),
        CodeContext::Assignment,
        "non-test def boundary prevents false TestCode classification"
    );
}

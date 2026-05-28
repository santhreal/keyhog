//! Non-test Go func stops test-function lookback.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_go_func_test_boundary() {
    let lines = vec!["func helper() {", r#"    token := "ghp_real_token_value""#];
    assert_eq!(
        infer_context(&lines, 1, None),
        CodeContext::Assignment,
        "regular func boundary must not inherit TestCode from unrelated tests"
    );
}

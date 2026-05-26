//! Equality comparison must not be classified as assignment.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_comparison_eq_not_assignment() {
    let lines = vec![r#"if status == "ready" {"#];
    assert_ne!(
        infer_context(&lines, 0, None),
        CodeContext::Assignment,
        "== comparison must not trigger assignment context"
    );
}

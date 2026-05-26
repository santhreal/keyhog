//! Go `_test.go` suffix forces TestCode context.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_go_test_file_suffix() {
    let lines = vec![r#"token := "ghp_abc123""#];
    assert_eq!(
        infer_context(&lines, 0, Some("pkg/auth_test.go")),
        CodeContext::TestCode,
        "Go *_test.go files are always test context"
    );
}

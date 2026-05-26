//! KH-GAP-019: `async fn test_*` bodies under `#[tokio::test]` are not TestCode.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_tokio_async_fn_test_body_is_test_code() {
    let lines = vec![
        "#[tokio::test]",
        "async fn integration() {",
        r#"    let key = "sk-proj-abc";"#,
    ];
    assert_eq!(
        infer_context(&lines, 2, None),
        CodeContext::TestCode,
        "async Rust test bodies under #[tokio::test] must classify as TestCode, not Assignment"
    );
}

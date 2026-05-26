//! `def test_*` header marks following assignment lines as TestCode.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_tokio_test_attribute() {
    let lines = vec![
        "def test_async_api():",
        r#"    key = "sk-proj-abc""#,
    ];
    assert_eq!(
        infer_context(&lines, 1, None),
        CodeContext::TestCode,
        "body inside Python test function must be test context"
    );
}

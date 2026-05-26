//! `_test.rs` filenames force TestCode context.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_rust_test_file_suffix() {
    let lines = vec![r#"let token = "sk-proj-real""#];
    assert_eq!(
        infer_context(&lines, 0, Some("src/auth_test.rs")),
        CodeContext::TestCode,
        "Rust *_test.rs files are always test context"
    );
}

//! Bare identifiers without quotes map to Unknown context.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_unknown_no_quotes_no_assignment() {
    let lines = vec!["invoke_handler"];
    assert_eq!(
        infer_context(&lines, 0, None),
        CodeContext::Unknown,
        "bare identifier line is unknown structural context"
    );
}

//! Out-of-range line index must return Unknown, not panic.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_out_of_bounds_returns_unknown() {
    let lines = vec!["key = value"];
    assert_eq!(
        infer_context(&lines, 99, None),
        CodeContext::Unknown,
        "line_idx past end must yield Unknown"
    );
}

//! YAML `key: value` mapping must infer Assignment context.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_assignment_yaml_mapping() {
    let lines = vec!["database_url: postgres://host/db"];
    assert_eq!(
        infer_context(&lines, 0, None),
        CodeContext::Assignment,
        "colon-space YAML mapping is assignment context"
    );
}

//! Docstring opened by assignment must not be flagged documentation.

use keyhog_scanner::context::documentation_line_flags;

#[test]
fn context_docstring_assignment_not_documentation() {
    let lines = vec![r#"x = """runtime doc""""#];
    let flags = documentation_line_flags(&lines);
    assert!(
        !flags[0],
        "assignment-prefixed triple-quoted string is code, not documentation"
    );
}

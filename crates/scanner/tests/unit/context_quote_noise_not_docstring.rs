//! A lone triple-quote buried in regular-quote noise must NOT open a docstring
//! and silently suppress every credential on the lines below it.

use keyhog_scanner::testing::context::documentation_line_flags;

#[test]
fn context_quote_noise_does_not_open_docstring() {
    // The first line carries a single `"""` preceded by an unterminated `"`
    // (quote noise from a randomized config dump / log line). It must not flip
    // the rest of the chunk into documentation mode.
    let lines = vec![
        r#"key "  :    """  :    ' ":  "  M49195NUQSS5Y3NI88IUJABUUEJM9QWZZERI"#,
        "EZAKsomecredentialbodyfollowsonthenextline",
    ];
    let flags = documentation_line_flags(&lines);
    assert!(
        !flags[1],
        "credential line below quote-noise `\"\"\"` must not be flagged documentation"
    );
}

#[test]
fn context_real_docstring_opener_still_flags_body() {
    // A genuine module/function docstring opener (triple-quote at a string-
    // opening position) must still mark the enclosed lines as documentation.
    let lines = vec![
        r#""""Module docstring."#,
        "still inside the docstring api_key = sk-demo",
        r#"""""#,
    ];
    let flags = documentation_line_flags(&lines);
    // The opener line itself is not flagged (consistent with the markdown-fence
    // contract: the delimiter line is code, the enclosed body is documentation).
    // What matters is that a genuine opener still suppresses its interior.
    assert!(
        flags[1],
        "docstring body line must be flagged documentation"
    );
    assert!(flags[2], "docstring closer line stays in documentation");
}

#[test]
fn context_line_comment_triple_quote_does_not_close_docstring() {
    let lines = vec![
        r#""""Module docstring."#,
        "inside before comment",
        r#"// """ comment text, not a Python docstring closer"#,
        "still inside the docstring api_key = sk-demo",
        r#"""""#,
    ];
    let flags = documentation_line_flags(&lines);
    assert!(
        flags[3],
        "triple quotes inside a line comment must not close docstring state"
    );
    assert!(flags[4], "real closer line stays in documentation");
}

#[test]
fn context_assignment_inside_docstring_does_not_close_docstring() {
    let lines = vec![
        r#""""Module docstring."#,
        "inside before assignment-like example",
        r#"example = """not a closer"#,
        "still inside the docstring api_key = sk-demo",
        r#"""""#,
    ];
    let flags = documentation_line_flags(&lines);
    assert!(
        flags[3],
        "assignment-prefixed triple quotes inside a docstring must not close docstring state"
    );
    assert!(flags[4], "real closer line stays in documentation");
}

#[test]
fn context_apostrophe_before_docstring_closer_still_closes_docstring() {
    let lines = vec![
        r#""""Module docstring."#,
        r#"the example doesn't leak """"#,
        "ordinary_code = true",
    ];
    let flags = documentation_line_flags(&lines);
    assert!(flags[1], "closer line remains documentation");
    assert!(
        !flags[2],
        "apostrophe text before a real closer must not keep docstring state open"
    );
}

#[test]
fn context_self_contained_docstring_line_is_documentation() {
    let lines = vec!["\"\"\"api_key = sk-demo\"\"\"", "ordinary_code = true"];
    let flags = documentation_line_flags(&lines);
    assert!(
        flags[0],
        "single-line docstring must be classified as documentation"
    );
    assert!(
        !flags[1],
        "single-line docstring must not leak documentation state to the next line"
    );
}

#[test]
fn context_double_slash_inside_regular_string_does_not_hide_docstring() {
    let lines = vec![
        r#"prefix = "https://example.test" """doc""""#,
        "ordinary_code = true",
    ];
    let flags = documentation_line_flags(&lines);
    assert!(
        !flags[1],
        "double slash inside a regular string must not corrupt docstring state"
    );
}

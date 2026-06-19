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

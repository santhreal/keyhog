use keyhog::subcommands::detectors::{
    fix_single_brace_in_verify_blocks_for_test as fix_single_brace_in_verify_blocks,
    rewrite_braces_for_test as rewrite_braces,
    rewrite_braces_in_string_literals_for_test as rewrite_braces_in_string_literals,
};

#[test]
fn rewrites_single_brace_to_double() {
    let (out, n) = rewrite_braces("https://api.example.com/{shop}/orders/{id}");
    assert_eq!(out, "https://api.example.com/{{shop}}/orders/{{id}}");
    assert_eq!(n, 2);
}

#[test]
fn leaves_already_doubled_alone() {
    let (out, n) = rewrite_braces("https://api.example.com/{{shop}}/orders/{{id}}");
    assert_eq!(out, "https://api.example.com/{{shop}}/orders/{{id}}");
    assert_eq!(n, 0);
}

#[test]
fn dotted_identifier_is_recognised() {
    let (out, n) = rewrite_braces("https://api.example.com/{companion.shop}/charge");
    assert_eq!(out, "https://api.example.com/{{companion.shop}}/charge");
    assert_eq!(n, 1);
}

#[test]
fn non_identifier_braces_left_intact() {
    let (out, n) = rewrite_braces("[A-Z]{4,6}");
    assert_eq!(out, "[A-Z]{4,6}");
    assert_eq!(n, 0);
}

#[test]
fn rewrites_only_inside_verify_block() {
    let toml = r#"
[detector]
id = "x"

[[detector.patterns]]
regex = "[A-Z]{4}"

[detector.verify]
url = "https://api.example.com/{shop}/orders"
"#;
    let (out, n) = fix_single_brace_in_verify_blocks(toml);
    assert_eq!(n, 1, "only the verify URL should be rewritten");
    assert!(
        out.contains("regex = \"[A-Z]{4}\""),
        "regex quantifier untouched"
    );
    assert!(out.contains("/{{shop}}/orders"), "verify URL rewritten");
}

#[test]
fn handles_string_with_escape_sequences() {
    let (out, n) =
        rewrite_braces_in_string_literals(r#"body = "Hello {name}, payload=\"{{value}}\"""#);
    assert!(out.contains("{{name}}"), "got: {out}");
    assert_eq!(n, 1);
}

#[test]
fn rewrite_is_noop_on_clean_file() {
    let toml = r#"
[detector]
id = "demo"

[detector.verify]
url = "https://api.example.com/{{companion.shop}}"
"#;
    let (out, n) = fix_single_brace_in_verify_blocks(toml);
    assert_eq!(n, 0);
    assert_eq!(out.trim(), toml.trim());
}

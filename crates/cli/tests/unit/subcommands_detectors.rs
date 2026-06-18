use keyhog::testing::{CliTestApi as _, API};

#[test]
fn rewrites_single_brace_to_double() {
    let (out, n) = API.rewrite_detector_braces("https://api.example.com/{shop}/orders/{id}");
    assert_eq!(out, "https://api.example.com/{{shop}}/orders/{{id}}");
    assert_eq!(n, 2);
}

#[test]
fn leaves_already_doubled_alone() {
    let (out, n) = API.rewrite_detector_braces("https://api.example.com/{{shop}}/orders/{{id}}");
    assert_eq!(out, "https://api.example.com/{{shop}}/orders/{{id}}");
    assert_eq!(n, 0);
}

#[test]
fn dotted_identifier_is_recognised() {
    let (out, n) = API.rewrite_detector_braces("https://api.example.com/{companion.shop}/charge");
    assert_eq!(out, "https://api.example.com/{{companion.shop}}/charge");
    assert_eq!(n, 1);
}

#[test]
fn non_identifier_braces_left_intact() {
    let (out, n) = API.rewrite_detector_braces("[A-Z]{4,6}");
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
    let (out, n) = API.fix_single_brace_in_verify_blocks(toml);
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
        API.rewrite_braces_in_string_literals(r#"body = "Hello {name}, payload=\"{{value}}\"""#);
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
    let (out, n) = API.fix_single_brace_in_verify_blocks(toml);
    assert_eq!(n, 0);
    assert_eq!(out.trim(), toml.trim());
}

#[test]
fn embedded_detector_loading_uses_core_fail_closed_loader() {
    let src = include_str!("../../src/subcommands/detectors.rs");
    assert!(
        src.contains("keyhog_core::load_embedded_detectors_or_fail()"),
        "detectors subcommand must share the core fail-closed embedded detector loader"
    );
    assert!(
        !src.contains("failed to parse embedded detector"),
        "detectors subcommand must not warn-and-continue on malformed embedded detector TOML"
    );
}

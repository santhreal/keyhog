#[test]
fn detector_compile_uses_runtime_regex_builder_before_scan() {
    let source = include_str!("../../../src/compiler/compiler_compile.rs");
    let start = source
        .find("pub(crate) fn compile_pattern(")
        .expect("compile_pattern present");
    let end = source[start..]
        .find("pub(crate) fn match_proves_keyword_nearby")
        .map(|offset| start + offset)
        .expect("compile_pattern boundary present");
    let body = &source[start..end];

    assert!(
        body.contains("shared_regex(spec.regex.as_str())"),
        "compile_pattern must dry-run detector regexes through the same shared RegexBuilder used by LazyRegex before a scan can start"
    );
    assert!(
        !body.contains("regex_syntax::Parser::new().parse(&spec.regex)"),
        "syntax-only detector validation misses builder size/flag failures and can leave a runtime-only never-match fallback"
    );
}

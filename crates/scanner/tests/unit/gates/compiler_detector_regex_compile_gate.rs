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
        body.contains("let regex = shared_regex(spec.regex.as_str())"),
        "compile_pattern must validate detector regexes through the same shared RegexBuilder used by LazyRegex before a scan can start"
    );
    assert!(
        body.contains("LazyRegex::detector_compiled(spec.regex.as_str(), regex)"),
        "compile_pattern must seed LazyRegex with the validated shared regex instead of compiling once for validation and again on warm/first scan"
    );
    assert!(
        !body.contains("regex_syntax::Parser::new().parse(&spec.regex)"),
        "syntax-only detector validation misses builder size/flag failures and can leave a runtime-only never-match fallback"
    );
}

#[test]
fn generated_plain_regexes_compile_before_scanner_construction() {
    let build = include_str!("../../../src/compiler/compiler_build.rs");
    assert!(
        build.contains("regex::Regex::new(&full_homoglyph_regex)")
            && build.contains("LazyRegex::plain_compiled(")
            && !build.contains("LazyRegex::plain(full_homoglyph_regex)"),
        "generated homoglyph/plain regexes must be validated and seeded during compiler build, not disabled by LazyRegex::get at first use"
    );

    let types = include_str!("../../../src/types.rs");
    assert!(
        types.contains("pub(crate) fn plain_compiled")
            && !types.contains("never_match_regex")
            && !types.contains("disabled for this run"),
        "LazyRegex must not hide construction-missed regex compile failures behind a never-match regex"
    );
}

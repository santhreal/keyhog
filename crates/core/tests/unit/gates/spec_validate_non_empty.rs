//! Gate `spec::validate`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn spec_validate_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec/validate.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "spec::validate: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "spec::validate: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        prod.contains("struct RegexAstCache")
            && prod.contains("HashMap<&'a str, Result<ast::Ast, String>>")
            && prod.contains("fn parse(&mut self, regex: &'a str) -> Result<&ast::Ast, &str>")
            && prod.matches("ast::parse::Parser::new()").count() == 1
            && prod.matches("regex_cache.parse(").count() >= 4
            && !prod.contains("regex::Regex::new(&pat.regex)"),
        "spec::validate: detector regex validation must parse each regex through the shared AST cache"
    );
}

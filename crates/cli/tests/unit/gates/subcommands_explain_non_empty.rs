//! Gate `subcommands::explain`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn subcommands_explain_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/explain.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "subcommands::explain: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "subcommands::explain: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        prod.contains("fn contains_ignore_ascii_case(")
            && prod.contains("fn strip_prefix_ignore_ascii_case")
            && !prod.contains(".to_lowercase()")
            && !prod.contains(".to_ascii_lowercase()"),
        "subcommands::explain must keep detector/service matching allocation-free and ASCII-case-insensitive"
    );
}

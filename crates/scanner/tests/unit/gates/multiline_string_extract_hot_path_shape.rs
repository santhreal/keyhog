//! Gate `multiline::string_extract`: plus-concat extraction stays allocation-light.

#[test]
fn plus_concatenation_does_not_collect_split_parts() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/multiline/string_extract.rs"
    );
    let source = std::fs::read_to_string(path).expect("multiline string_extract source readable");
    let production = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    // Quote-aware split: extraction must stream segments from the lazy
    // `split_concatenation_operators` iterator (which only breaks on `+` outside
    // quoted spans), counting parts inline — NOT collect a Vec. A blind
    // `content_to_split.split('+')` is forbidden because it shreds base64 values
    // whose alphabet contains `+`.
    assert!(
        production.contains("let mut part_count = 0usize;")
            && production.contains("for part in split_concatenation_operators(content_to_split)"),
        "plus-concat extraction must stream segments from the quote-aware iterator"
    );
    assert!(
        !production.contains("content_to_split.split('+')"),
        "plus-concat extraction must not blind-split on '+' (it shreds in-quote base64 '+')"
    );
    assert!(
        production
            .contains("fn split_concatenation_operators(expr: &str) -> impl Iterator<Item = &str>"),
        "the quote-aware splitter must yield a lazy iterator, not allocate"
    );
    assert!(
        !production.contains(".split('+').collect()")
            && !production.contains("let parts: Vec<&str>")
            && !production.contains("-> Vec<&str>"),
        "plus-concat extraction must not allocate a Vec of split parts"
    );
    let extract_prefix = production
        .split("pub(crate) fn extract_prefix")
        .nth(1)
        .and_then(|tail| {
            tail.split("pub(crate) fn fragment_assignment_name_is_credential_like")
                .next()
        })
        .expect("extract_prefix body present");
    assert!(
        extract_prefix.contains("String::with_capacity(var_name.len())")
            && extract_prefix.contains("head.eq_ignore_ascii_case(b\"part\")")
            && !extract_prefix.contains(".to_lowercase()")
            && !extract_prefix.contains(".replace(\"part\"")
            && !extract_prefix.contains(".replace(['_', '-']")
            && !extract_prefix.contains(".to_string()"),
        "extract_prefix must normalize fragment names in one pass without lowercase/replace/to_string allocation chains"
    );
}

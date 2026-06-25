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

    assert!(
        production.contains("let mut part_count = 0usize;")
            && production.contains("for part in content_to_split.split('+')"),
        "plus-concat extraction must stream split parts directly"
    );
    assert!(
        !production.contains(".split('+').collect()")
            && !production.contains("let parts: Vec<&str>"),
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

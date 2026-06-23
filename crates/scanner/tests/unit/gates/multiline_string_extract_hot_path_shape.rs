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
}

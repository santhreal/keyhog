//! Gate: structured JSON line attribution must be batched, not one search per value.

#[test]
fn structured_json_line_lookup_batched() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let json = std::fs::read_to_string(root.join("src/structured/parsers/json.rs"))
        .expect("json parser readable");
    let line = std::fs::read_to_string(root.join("src/structured/parsers/line.rs"))
        .expect("line parser readable");

    assert!(
        json.contains("resolve_line_numbers(text, &anchors)"),
        "JSON structured parsers must resolve extracted line anchors in one batch"
    );
    assert!(
        !json.contains("find_line_number"),
        "JSON structured parsers must not perform one full-document lookup per extracted value"
    );
    assert!(
        line.contains("AhoCorasick::new(patterns.iter().copied())")
            && line.contains("find_overlapping_iter(text)")
            && line.contains("build_line_starts(text)"),
        "structured line resolver must use one multi-pattern pass plus one line-start index"
    );
}

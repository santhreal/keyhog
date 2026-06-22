//! Gate: structured JSON line attribution must be batched, not one search per value.

#[test]
fn structured_json_line_lookup_batched() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let json = std::fs::read_to_string(root.join("src/structured/parsers/json.rs"))
        .expect("json parser readable");
    let yaml = std::fs::read_to_string(root.join("src/structured/parsers/yaml.rs"))
        .expect("yaml parser readable");
    let line = std::fs::read_to_string(root.join("src/structured/parsers/line.rs"))
        .expect("line parser readable");

    assert!(
        json.contains("finalize_pending_pairs(text, pending)"),
        "JSON structured parsers must resolve extracted line anchors through the shared batch finalizer"
    );
    assert!(
        !json.contains("find_line_number"),
        "JSON structured parsers must not perform one full-document lookup per extracted value"
    );
    assert!(
        yaml.contains("finalize_pending_pairs(text, pending)"),
        "YAML structured parsers must resolve extracted line anchors through the shared batch finalizer"
    );
    assert!(
        !yaml.contains("find_line_number"),
        "YAML structured parsers must not perform one full-document lookup per extracted value"
    );
    assert!(
        line.contains("AhoCorasick::new(patterns.iter().copied())")
            && line.contains("find_overlapping_iter(text)")
            && line.contains("build_line_starts(text)"),
        "structured line resolver must use one multi-pattern pass plus one line-start index"
    );
}

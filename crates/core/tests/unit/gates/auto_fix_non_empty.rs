//! Gate `auto_fix`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn auto_fix_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/auto_fix.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "auto_fix: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "auto_fix: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        prod.contains("fn service_entry_matches(")
            && prod.contains("contains_ignore_ascii_case(")
            && prod.contains("severity.as_str()")
            && !prod.contains(".to_lowercase()")
            && !prod.contains("format!(\"{severity:?}\")"),
        "auto_fix: service/remediation matching must stay allocation-free and use canonical severity labels"
    );
}

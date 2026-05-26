//! Gate `verify::multi_step`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn verify_multi_step_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/multi_step.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "verify::multi_step: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "verify::multi_step: todo!/unimplemented! forbidden in non-test source"
    );
}

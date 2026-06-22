//! Gate `spec::load`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn spec_load_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec/load.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "spec::load: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "spec::load: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        prod.contains("let mut contents = String::with_capacity(len as usize);")
            && !prod.contains("let mut contents = String::new();"),
        "spec::load: detector TOML reads must pre-size the String from capped metadata length"
    );
}

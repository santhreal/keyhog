//! Gate `config`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn config_non_empty() {
    for path in [
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/limits.rs"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/schema.rs"),
    ] {
        let src = std::fs::read_to_string(path).expect("source readable");
        assert!(
            src.trim().len() >= 20,
            "config: expected substantive source, got {} trimmed bytes",
            src.trim().len()
        );
        let prod = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
            "config: todo!/unimplemented! forbidden in non-test source"
        );
    }
}

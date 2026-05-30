//! Gate `filesystem`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn filesystem_non_empty() {
    for rel in [
        "src/filesystem.rs",
        "src/filesystem/extract.rs",
        "src/filesystem/filter.rs",
    ] {
        let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
        let src = std::fs::read_to_string(&path).expect("source readable");
        assert!(
            src.trim().len() >= 20,
            "filesystem: expected substantive source in {rel}, got {} trimmed bytes",
            src.trim().len()
        );
        let prod = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
            "filesystem: todo!/unimplemented! forbidden in non-test source {rel}"
        );
    }
}

//! Gate `subcommands::detectors`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn subcommands_detectors_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/detectors.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "subcommands::detectors: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "subcommands::detectors: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        src.contains("crate::orchestrator_config::load_detectors_embedded_or_fail")
            && !src.contains("fn load_embedded_or_bail("),
        "subcommands::detectors must use the canonical embedded detector loader instead of owning a divergent local copy"
    );
}

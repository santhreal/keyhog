//! Gate `subcommands::scan_system`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn subcommands_scan_system_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/scan_system.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "subcommands::scan_system: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "subcommands::scan_system: todo!/unimplemented! forbidden in non-test source"
    );
}

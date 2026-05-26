//! Gate `subcommands::scan_system`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn subcommands_scan_system_no_inline_tests() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan_system.rs"
    );
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "subcommands::scan_system: move inline tests to crates/cli/tests/"
    );
}

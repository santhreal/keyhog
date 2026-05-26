//! Gate `subcommands::explain`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn subcommands_explain_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/explain.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "subcommands::explain: move inline tests to crates/cli/tests/"
    );
}

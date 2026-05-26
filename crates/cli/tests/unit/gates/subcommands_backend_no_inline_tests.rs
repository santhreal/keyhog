//! Gate `subcommands::backend`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn subcommands_backend_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/backend.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "subcommands::backend: move inline tests to crates/cli/tests/"
    );
}

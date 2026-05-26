//! Gate `subcommands::diff`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn subcommands_diff_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/diff.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "subcommands::diff: move inline tests to crates/cli/tests/"
    );
}

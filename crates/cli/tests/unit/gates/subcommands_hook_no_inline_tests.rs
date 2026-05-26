//! Gate `subcommands::hook`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn subcommands_hook_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/hook.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "subcommands::hook: move inline tests to crates/cli/tests/"
    );
}

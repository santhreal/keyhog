//! Gate `orchestrator_config`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn orchestrator_config_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator_config.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "orchestrator_config: move inline tests to crates/cli/tests/"
    );
}

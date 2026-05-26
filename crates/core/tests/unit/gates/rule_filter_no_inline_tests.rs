//! Gate `rule_filter`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn rule_filter_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/rule_filter.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "rule_filter: move inline tests to crates/core/tests/"
    );
}

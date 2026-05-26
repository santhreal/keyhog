//! Gate `slack`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn slack_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/slack.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "slack: move inline tests to crates/sources/tests/"
    );
}

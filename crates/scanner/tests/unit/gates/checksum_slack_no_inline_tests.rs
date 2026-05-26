//! Gate `checksum::slack`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn checksum_slack_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/checksum/slack.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "checksum::slack: move inline tests to crates/scanner/tests/"
    );
}

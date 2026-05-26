//! Gate `confidence::signals`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn confidence_signals_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/confidence/signals.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "confidence::signals: move inline tests to crates/scanner/tests/"
    );
}

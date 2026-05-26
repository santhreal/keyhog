//! Gate `report::text`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn report_text_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/report/text.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "report::text: move inline tests to crates/core/tests/"
    );
}

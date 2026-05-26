//! Gate `report::sarif`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn report_sarif_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/report/sarif.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "report::sarif: move inline tests to crates/core/tests/"
    );
}

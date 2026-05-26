//! Gate `engine::scan_filters`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn engine_scan_filters_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/scan_filters.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "engine::scan_filters: move inline tests to crates/scanner/tests/"
    );
}

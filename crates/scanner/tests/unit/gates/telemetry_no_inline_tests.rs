//! Gate `telemetry`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn telemetry_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/telemetry.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "telemetry: move inline tests to crates/scanner/tests/"
    );
}

//! Gate `calibration`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn calibration_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/calibration.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "calibration: move inline tests to crates/core/tests/"
    );
}

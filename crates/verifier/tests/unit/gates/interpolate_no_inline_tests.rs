//! Gate `interpolate`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn interpolate_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/interpolate.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "interpolate: move inline tests to crates/verifier/tests/"
    );
}

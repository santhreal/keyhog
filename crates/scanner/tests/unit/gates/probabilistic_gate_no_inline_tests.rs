//! Gate `probabilistic_gate`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn probabilistic_gate_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/probabilistic_gate.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "probabilistic_gate: move inline tests to crates/scanner/tests/"
    );
}

//! Gate `probabilistic_gate`: modularity file cap (500 LOC).

#[test]
fn probabilistic_gate_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/probabilistic_gate.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "probabilistic_gate: {lines} lines exceeds 500-line cap - split module"
    );
}

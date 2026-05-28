//! Gate `binary::ghidra`: modularity file cap (500 LOC).

#[test]
fn binary_ghidra_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/binary/ghidra.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "binary::ghidra: {lines} lines exceeds 500-line cap - split module"
    );
}

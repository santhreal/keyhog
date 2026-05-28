//! Gate `spec`: modularity file cap (500 LOC).

#[test]
fn spec_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "spec: {lines} lines exceeds 500-line cap - split module"
    );
}

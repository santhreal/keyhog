//! Gate `sources`: modularity file cap (500 LOC).

#[test]
fn sources_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/sources.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "sources: {lines} lines exceeds 500-line cap - split module"
    );
}

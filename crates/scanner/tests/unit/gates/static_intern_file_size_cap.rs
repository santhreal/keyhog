//! Gate `static_intern`: modularity file cap (500 LOC).

#[test]
fn static_intern_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/static_intern.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "static_intern: {lines} lines exceeds 500-line cap — split module"
    );
}

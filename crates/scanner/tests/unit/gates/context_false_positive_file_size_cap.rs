//! Gate `context::false_positive`: modularity file cap (500 LOC).

#[test]
fn context_false_positive_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/context/false_positive.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "context::false_positive: {lines} lines exceeds 500-line cap — split module"
    );
}
